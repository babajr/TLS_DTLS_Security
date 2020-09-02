#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/file.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#define MAXLINE     4096
#define TRUE        1

char Usage[] =
"Usage: dtls_udp_echo [options] [address]\n"
"Options:\n"
"        -L      local address\n"
"        -p      port (Default: 55000)\n";

void start_client(char *local_address, int port) 
{
	int fd;
	struct sockaddr_in local_addr;
	char buff[MAXLINE];
    char recvLine[MAXLINE];
	int len, ret, flags, error_recv;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;

    char caCertLoc[] = "../../../Certificates/root-ca/root-ca.cert.pem";
    char clientCertLoc[] = "../../../Certificates/client/client.cert.pem";
    char clientKeyLoc[] = "../../../Certificates/client/private/client.key.pem";

	memset(&local_addr, 0, sizeof(struct sockaddr_in));

	if (inet_pton(AF_INET, local_address, &local_addr.sin_addr) < 1) 
	{
		printf("Error and/or invalid IP address");
        exit(-1);
	}
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(port);
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) 
	{
		perror("socket");
		exit(-1);
	}

    /* non-blocking socket */
    flags = fcntl(fd, F_GETFL, 0);
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("ERROR: failed to set non-blocking");
        close(fd);
        exit(EXIT_FAILURE);
    }

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(DTLS_client_method());
	/* Load certificates into ctx variable */
    if (SSL_CTX_load_verify_locations(ctx, caCertLoc, 0) != 1)
    { 
        printf("\nError: please check the file!");
        goto cleanup_ctx;
    }

	if (SSL_CTX_use_certificate_file(ctx, clientCertLoc, SSL_FILETYPE_PEM) != 1)
	{
       	printf("\nERROR: no certificate found!");
        goto cleanup_ctx;
    }
	if (SSL_CTX_use_PrivateKey_file(ctx, clientKeyLoc, SSL_FILETYPE_PEM) != 1)
	{
    	printf("\nERROR: no private key found!");
        goto cleanup_ctx;
    }

	if (SSL_CTX_check_private_key (ctx) != 1)
	{
        printf("\nERROR: invalid private key!");
        goto cleanup_ctx;
    }

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth (ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);

    
    if((ret = connect(fd, (struct sockaddr*) &local_addr, sizeof(local_addr))) == -1) 
    {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto cleanup_ctx;
    }

    ssl = SSL_new(ctx);
   
    /* Create BIO, connect and set to already connected */
    bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &local_addr);
    
    SSL_set_bio(ssl, bio, bio);
    
    /* Connect to SSL on the server side */
    while((ret = SSL_connect(ssl)) != 1) 
    {
        error_recv = SSL_get_error(ssl, ret);
        switch(errno)
        {
            case ECONNREFUSED:
            case EINPROGRESS:
            case EWOULDBLOCK:
                continue;
                break;

            default: 
                fprintf(stderr, "ERROR: failed to ssl_connect()\n");
                goto cleanup;
        }
        switch(error_recv)
        {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                continue;

            default:
            {
                fprintf(stderr, "ERROR: failed to ssl_connect()\n");
                goto cleanup;
            }
        }
    }

    while (TRUE) 
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
        while((ret = SSL_write(ssl, buff, len)) != len) 
        {
            error_recv = SSL_get_error(ssl, ret);
            switch(error_recv)
            {
                case SSL_ERROR_WANT_WRITE:
                    continue;
                    
                default:
                {
                    fprintf(stderr, "ERROR: failed to write entire message\n");
                    fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int) len);
                    goto cleanup;
                }
            }
        }

        /* Read the server data into our buff array */
        memset(buff, 0, sizeof(buff));
        while((ret = SSL_read(ssl, buff, sizeof(buff)-1)) < 0) 
        {
            error_recv = SSL_get_error(ssl, ret);
            switch(error_recv)
            {
                case SSL_ERROR_WANT_READ:
                    continue;
                    
                default:
                {
                    fprintf(stderr, "ERROR: failed to read\n");
                    goto cleanup;
                }
            }
        }

        /* Print to stdout any data the server sends */
        printf("Server: %s\n", buff);

        if(!(strncmp(buff, "exit", 4)))
        {
            break;
        }
    }

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
cleanup_ctx:
    close(fd);
    SSL_CTX_free(ctx);
}

int main(int argc, char **argv)
{
	int port = 55000;
	int length = 100;
	int messagenumber = 5;
	char local_addr[20];

	memset(local_addr, 0, INET_ADDRSTRLEN+1);

	argc--;
	argv++;

	while (argc >= 1) 
	{
		if (strcmp(*argv, "-L") == 0) 
		{
			if (--argc < 1) 
                goto 
                cmd_err;

			strncpy(local_addr, *++argv, 15);
		}
		else if	(strcmp(*argv, "-p") == 0) 
		{
			if (--argc < 1) 
                goto cmd_err;

			port = atoi(*++argv);
		}

		argc--;
		argv++;
	}

	start_client(local_addr, port);

	return 0;

cmd_err:
	fprintf(stderr, "%s\n", Usage);
	return 1;
}
