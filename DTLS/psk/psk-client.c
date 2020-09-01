/*
* Blocking DTLS Client with PSK example for learning purpose.
*/

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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#define MAXLINE         4096
#define TRUE            1
#define dhParamFile     "./../../Certificates/psk/dh2048.pem"
#define PSK_KEY_LEN     4

char Usage[] =
"Usage: dtls_udp_echo [options] [address]\n"
"Options:\n"
"        -L      local address\n"
"        -p      port (Default: 55000)\n";


static inline unsigned int My_Psk_Client_Cb(SSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;
    (void)key_max_len;

    /* identity is OpenSSL testing default for openssl s_client, keep same*/
    strncpy(identity, "Client", id_max_len);

    /* test key n hex is 0x1a2b3c4d , in decimal 439,041,101, we're using
     * unsigned binary */
    key[0] = 11;
    key[1] = 22;
    key[2] = 33;
    key[3] = 44;

    return PSK_KEY_LEN;
}

void start_client(char *local_address, int port) 
{
	int fd;
	struct sockaddr_in local_addr;
	char buff[MAXLINE];
    char recvLine[MAXLINE];
	int len, ret;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;

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

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(DTLS_client_method());
	/* Load certificates into ctx variable */
    SSL_CTX_set_psk_client_callback(ctx, My_Psk_Client_Cb);

    DH *dh_2048 = NULL;
    FILE *paramfile;
    paramfile = fopen(dhParamFile, "r");
    if (paramfile) 
    {
      dh_2048 = PEM_read_DHparams(paramfile, NULL, NULL, NULL);
      fclose(paramfile);
    }
    if (SSL_CTX_set_tmp_dh(ctx, dh_2048) != 1) 
    {
        printf("Fatal error: server set temp DH params returned %d\n", ret);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth (ctx, 2);
    SSL_CTX_set_read_ahead(ctx, 1);

	/* Client attempts to make a connection on a socket */
    if (connect(fd, (struct sockaddr *) &local_addr, sizeof(struct sockaddr_in))) 
    {
	    perror("connect");
	    goto cleanup_ctx;
    }

    ssl = SSL_new(ctx);
   
    /* Create BIO, connect and set to already connected */
    bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &local_addr);
    
    SSL_set_bio(ssl, bio, bio);
    
    if (SSL_connect(ssl) <= 0) 
    {
        printf("SSL_connect failed");
        goto cleanup;
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
