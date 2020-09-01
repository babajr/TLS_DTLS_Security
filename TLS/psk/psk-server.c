/*
* Blocking TLS Server with PSK example for learning purpose.
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

#define DEFAULT_PORT    55000
#define TRUE            1
#define PSK_KEY_LEN 	4
#define dhParamFile    "./../../Certificates/psk/dh2048.pem"

/* callback to identify which psk key to use */
static unsigned int my_psk_server_cb(SSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)key_max_len;

    if (strncmp(identity, "Client", 7) != 0) {
        return 0;
    }

    key[0] = 11;
    key[1] = 22;
    key[2] = 33;
    key[3] = 44;

    return PSK_KEY_LEN;
}

/* Create and set up SSL CTX context */
SSL_CTX *create_context()
{
    SSL_CTX* ctx;
	DH *dh_2048 = NULL;
    FILE *paramfile = NULL;
	int ret;

    /* Create and initialize SSL_CTX */
    if ((ctx = SSL_CTX_new(TLSv1_2_server_method())) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create SSL_CTX\n");
        goto cleanup;
    }

	/* Use PSK suite for providing security */
    SSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);

    if ((ret = SSL_CTX_use_psk_identity_hint(ctx, "ssl server")) != 1) 
	{
        printf("Fatal error : ctx use psk identity hint returned %d\n", ret);
        goto cleanup;
    }

    paramfile = fopen(dhParamFile, "r");

    if (paramfile) 
    {
      dh_2048 = PEM_read_DHparams(paramfile, NULL, NULL, NULL);
      fclose(paramfile);
    }

    if ((ret = SSL_CTX_set_tmp_dh(ctx, dh_2048)) != 1) 
    {
        printf("Fatal error: server set temp DH params returned %d\n", ret);
    }

	SSL_CTX_set_verify(ctx, SSL_VERIFY_CLIENT_ONCE, NULL);
    SSL_CTX_set_verify_depth (ctx, 2);
    SSL_CTX_set_read_ahead(ctx, 1);

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
    int shutdown = 0;
    int ret;
    SSL* ssl;
    SSL_CTX* ctx = NULL;

    /* Initialize SSL */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_ssl_algorithms();

    /* Create SSL CTX context */
    if((ctx = create_context()) == 0)
    {
        printf("Unable to create ctx\n");
        exit(EXIT_FAILURE);
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
    servAddr.sin_family      = AF_INET;             
    servAddr.sin_port        = htons(DEFAULT_PORT); 
    servAddr.sin_addr.s_addr = INADDR_ANY;          

    /* Bind the server socket to our port i.e. assigning a name to a socket */
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
    if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size)) == -1) 
    {
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
    ret = SSL_accept(ssl);
    if (ret != 1) 
    {
        fprintf(stderr, "SSL_accept error = %d\n",
            SSL_get_error(ssl, ret));
        
        goto clean_ssl;
    }

    printf("Client connected successfully\n");

    /* Continue to accept clients until exit command is issued */
    while (TRUE) 
    {
        /* Read the client data into our buff array */
        memset(buff, 0, sizeof(buff));

        if (SSL_read(ssl, buff, sizeof(buff)) == -1) 
        {
            fprintf(stderr, "ERROR: failed to read\n");
            goto clean_ssl;
        }

        /* Print to stdout any data the client sends */
        printf("Client: %s\n", buff);

        /* Write our reply into buff */
        len = strnlen(buff, sizeof(buff));

        /* Reply back to the client */
        if (SSL_write(ssl, buff, len) != len) 
        {
            fprintf(stderr, "ERROR: failed to write\n");
            goto clean_ssl;
        }     

        /* Check for server exit command */
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
