/*
* Blocking TLS Client with x509 Certificates example for learning purpose.
*/

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* SSL */
#include <openssl/bio.h>
#include <openssl/ssl.h>

#define DEFAULT_PORT 55000

SSL_CTX *create_context()
{
    SSL_CTX* ctx;

    char caCertLoc[] = "../../Certificates/root-ca/root-ca.cert.pem";
    char clientCertLoc[] = "../../Certificates/client/client.cert.pem";
    char clientKeyLoc[] = "../../Certificates/client/private/client.key.pem";

    /* Create and initialize SSL_CTX */
    if ((ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL) 
    {
        fprintf(stderr, "ERROR: failed to create SSL_CTX\n");
        goto cleanup;
    }
    /* Load certificates into ctx variable */
    if (SSL_CTX_load_verify_locations(ctx, caCertLoc, 0) != 1) 
    {
        fprintf(stderr, "Error loading %s, please check the file.\n", caCertLoc);
        goto cleanup;
    }

    /* Load the client's certificate */
    if (SSL_CTX_use_certificate_file(ctx, clientCertLoc, SSL_FILETYPE_PEM) != 1) 
    {
        fprintf(stderr, "Cannot load client's certificate file\n");
        goto cleanup;
    }

    /* Load the client's key */
    if (SSL_CTX_use_PrivateKey_file(ctx, clientKeyLoc, SSL_FILETYPE_PEM) != 1) 
    {
        fprintf(stderr, "Cannot load client's key file\n");
        goto cleanup;
    }

    /* Verify that the client's certificate and the key match */
    if (SSL_CTX_check_private_key(ctx) != 1) 
    {
        fprintf(stderr, "Client's certificate and key don't match\n");
        goto cleanup;
    }
    
    /* We won't handle incomplete read/writes due to renegotiation */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    /* Specify that we need to verify the server's certificate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* We accept only certificates signed only by the CA himself */
    SSL_CTX_set_verify_depth(ctx, 1);

    return ctx;

cleanup:
    SSL_CTX_free(ctx);
    return 0;
}

int main(int argc, char** argv)
{
    int sockfd;
    struct sockaddr_in servAddr;
    char buff[256];
    size_t len;
    int ret;
    SSL* ssl;
    SSL_CTX* ctx = NULL;

    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_ssl_algorithms();

    if((ctx = create_context()) == 0)
    {
        printf("Unable to create ctx\n");
        exit(EXIT_FAILURE);
    }
    
    /* Check for proper calling convention */
    if (argc != 2) 
    {
        printf("usage: %s <IPv4 address>\n", argv[0]);
        return 0;
    }

	/* Create a socket for communication */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
    {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        SSL_CTX_free(ctx); 
        exit(EXIT_FAILURE);
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;             
    servAddr.sin_port   = htons(DEFAULT_PORT); 

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) != 1) 
    {
        fprintf(stderr, "ERROR: invalid address\n");
        goto ctx_cleanup;
    }

    /* Connect to the server */
    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr))) == -1) 
    {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto ctx_cleanup;
    }
    
    /* Create a SSL object */
    if ((ssl = SSL_new(ctx)) == NULL) 
    {
        fprintf(stderr, "ERROR: failed to create SSL object\n");
        ret = -1;
        goto ctx_cleanup;
    }

    /* Attach SSL to the socket */
    if ((ret = SSL_set_fd(ssl, sockfd)) != 1) 
    {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }

    /* Connect to SSL on the server side */
    if ((ret = SSL_connect(ssl)) != 1) 
    {
        fprintf(stderr, "error: failed to connect to ssl\n");
        goto cleanup;
    }
    while(1)
    {
        /* Get a message for the server from stdin */
        printf("Message for server: ");
        memset(buff, 0, sizeof(buff));
        if (fgets(buff, sizeof(buff), stdin) == NULL) 
        {
            fprintf(stderr, "ERROR: failed to get message for server\n");
            ret = -1;
            goto cleanup;
        }
        len = strnlen(buff, sizeof(buff));

        /* Send the message to the server */
        if ((ret = SSL_write(ssl, buff, len)) != len) 
        {
            fprintf(stderr, "ERROR: failed to write entire message\n");
            fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int) len);
            goto cleanup;
        }

        /* Read the server data into our buff array */
        memset(buff, 0, sizeof(buff));
        if ((ret = SSL_read(ssl, buff, sizeof(buff)-1)) == -1) 
        {
            fprintf(stderr, "ERROR: failed to read\n");
            goto cleanup;
        }

        /* Print to stdout any data the server sends */
        printf("Server: %s\n", buff);

        if(!(strncmp(buff, "exit", 4)))
        {
            break;
        }
    }
    
    /* Cleanup and return */
cleanup:
    SSL_free(ssl);     
ctx_cleanup:
    SSL_CTX_free(ctx);  
socket_cleanup:
    close(sockfd); 

    return 0;               
}
