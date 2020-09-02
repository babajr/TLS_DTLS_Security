
/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <errno.h>

/* SSL */
#include <openssl/bio.h>
#include <openssl/ssl.h>

#define DEFAULT_PORT    55000
#define TRUE            1

SSL_CTX *create_context()
{
    SSL_CTX* ctx;

    char caCertLoc[] = "../../../Certificates/root-ca/root-ca.cert.pem";
    char servCertLoc[] = "../../../Certificates/server/server.cert.pem";
    char servKeyLoc[] = "../../../Certificates/server/private/server.key.pem";

    /* Create and initialize SSL_CTX */
    if ((ctx = SSL_CTX_new(TLSv1_2_server_method())) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create SSL_CTX\n");
        goto cleanup;
    }

    /* Load CA certificates */
    if (SSL_CTX_load_verify_locations(ctx,caCertLoc,0) != 1)
    {
        printf("Error loading %s, please check the file.\n", caCertLoc);
        goto cleanup;
    }

    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(caCertLoc));

    /* Load server certificates */
    if (SSL_CTX_use_certificate_file(ctx, servCertLoc, SSL_FILETYPE_PEM) != 1) 
    {
        printf("Error loading %s, please check the file.\n", servCertLoc);
        goto cleanup;
    }

    /* Load server Keys */
    if (SSL_CTX_use_PrivateKey_file(ctx, servKeyLoc, SSL_FILETYPE_PEM) != 1)
    {
        printf("Error loading %s, please check the file.\n", servKeyLoc);
        goto cleanup;
    }

    /* We've loaded both certificate and the key, check if they match */
    if (SSL_CTX_check_private_key(ctx) != 1) 
    {
        printf("Server's certificate and the key don't match\n");
        goto cleanup;
    }

    /* We won't handle incomplete read/writes due to renegotiation */
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    
    /* Specify that we need to verify the client as well */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, NULL);

    /* We accept only certificates signed only by the CA himself */
    SSL_CTX_set_verify_depth(ctx, 1);

    return ctx;

    cleanup:
    SSL_CTX_free(ctx);
    return 0;
}

int main()
{
    int sockfd;
    int connd;
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t size = sizeof(clientAddr);
    char buff[256];
    size_t len;
    int flags = 0;
    int ret, error_recv;
    SSL* ssl;
    SSL_CTX* ctx = NULL;

    /* Initialize SSL */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_ssl_algorithms();

    
    if((ctx = create_context()) == 0)
    {
        printf("Unable to create ctx\n");
        exit(EXIT_FAILURE);
    }
  
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
    {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    /* non-blocking socket */
    flags = fcntl(sockfd, F_GETFL, 0);
    if(fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("ERROR: failed to set non-blocking");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family      = AF_INET;             
    servAddr.sin_port        = htons(DEFAULT_PORT); 
    servAddr.sin_addr.s_addr = INADDR_ANY;          

    /* Bind the server socket to our port */
    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) 
    {
        fprintf(stderr, "ERROR: failed to bind\n");
        SSL_CTX_free(ctx);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    /* Listen for a new connection, allow 5 pending connections */
    if (listen(sockfd, 5) == -1) 
    {
        fprintf(stderr, "ERROR: failed to listen\n");
        SSL_CTX_free(ctx);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Waiting for a connection...\n");
        
    /* Accept client connections */
    while((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size)) < 0) 
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            continue;

        fprintf(stderr, "ERROR: failed to accept the connection\n\n");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    /* Create a SSL object */
    if ((ssl = SSL_new(ctx)) == NULL) 
    {
        fprintf(stderr, "ERROR: failed to create SSL object\n");
        goto clean_sock_ctx;
    }

    /* Attach SSL to the socket */
    SSL_set_fd(ssl, connd);
    /* Establish TLS connection */
    while((ret = SSL_accept(ssl)) != 1) 
    {
        error_recv = SSL_get_error(ssl, ret);
        switch(error_recv)
        {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                continue;
                
            default:
            {
                fprintf(stderr, "ERROR: failed to ssl_accept()\n");
                goto clean_ssl;
            }
        }
    }

    printf("Client connected successfully\n");

    /* Continue to accept clients until shutdown is issued */
    while (TRUE) 
    {
        /* Read the client data into our buff array */
        memset(buff, 0, sizeof(buff));

        while((ret = SSL_read(ssl, buff, sizeof(buff))) < 0) 
        {
            error_recv = SSL_get_error(ssl, ret);
            switch(error_recv)
            {
                case SSL_ERROR_WANT_READ:
                    continue;

                default:
                {
                    fprintf(stderr, "ERROR: failed to read\n");
                    goto clean_ssl;
                }
            }
        }

        /* Print to stdout any data the client sends */
        printf("Client: %s\n", buff);

        /* Write our reply into buff */
        len = strnlen(buff, sizeof(buff));

        /* Reply back to the client */
        while((ret = SSL_write(ssl, buff, len)) != len) 
        {
            error_recv = SSL_get_error(ssl, ret);
            switch(error_recv)
            {
                case SSL_ERROR_WANT_WRITE:
                    continue;

                default:
                {
                    fprintf(stderr, "ERROR: failed to write\n");
                    goto clean_ssl;
                }
            }
        }     

        /* Check for server shutdown command */
        if (strncmp(buff, "exit", 4) == 0) 
        {
            printf("Exit command issued!\n");
            break;
        }         
    }

    printf("Shutdown complete\n");

    /* Cleanup and return */
clean_ssl:
    SSL_free(ssl);

clean_sock_ctx:
    close(connd);
    SSL_CTX_free(ctx);  
    close(sockfd); 

    return 0;           
}
