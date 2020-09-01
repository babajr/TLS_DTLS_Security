/*
* Blocking DTLS Server with x509 certificates example for learning purpose.
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

#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16

unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

char Usage[] =
"Usage: dtls_udp [options] [address]\n"
"Options:\n"
"        -L      local address\n"
"        -p      port (Default: 55000)\n";

static pthread_mutex_t* mutex_buf = NULL;

static void locking_function(int mode, int n, const char *file, int line) 
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&mutex_buf[n]);
	else
		pthread_mutex_unlock(&mutex_buf[n]);
}

static unsigned long id_function(void) 
{
	return (unsigned long) pthread_self();
}

int THREAD_setup() 
{
	int i;

	mutex_buf = (pthread_mutex_t*) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!mutex_buf)
		return 0;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&mutex_buf[i], NULL);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	return 1;
}

int THREAD_cleanup() 
{
	int i;

	if (!mutex_buf)
		return 0;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
	pthread_mutex_destroy(&mutex_buf[i]);
	free(mutex_buf);
	mutex_buf = NULL;

	return 1;
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	struct sockaddr_in server_addr;

	/* Initialize a random secret */
	if (!cookie_initialized)
	{
        if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
        {
        	printf("error setting random cookie secret\n");
        	return 0;
        }
        cookie_initialized = 1;
	}

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &server_addr);

	/* Create buffer with peer's address and port */
	length = 0;
	length += sizeof(struct in_addr);
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
	{
	    printf("out of memory\n");
	    return 0;
	}

	memcpy(buffer, &server_addr.sin_port, sizeof(in_port_t));
	memcpy(buffer + sizeof(server_addr.sin_port), &server_addr.sin_addr, sizeof(struct in_addr));

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH, 
                (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	struct sockaddr_in server_addr;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &server_addr);

	/* Create buffer with peer's address and port */
	length = 0;
	length += sizeof(struct in_addr);
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
	{
    	    printf("out of memory\n");
	    return 0;
	}

	memcpy(buffer, &server_addr.sin_port, sizeof(in_port_t));
	memcpy(buffer + sizeof(in_port_t), &server_addr.sin_addr, sizeof(struct in_addr));

        /* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
	    return 1;

	return 0;
}

struct pass_info {
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	SSL *ssl;
};

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) 
{
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}

void* connection_handle(void *info) 
{	
	ssize_t len;
	char buff[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	struct pass_info *pinfo = (struct pass_info*) info;
	SSL *ssl = pinfo->ssl;
	int fd, reading = 0, ret;
    int recvLen;
	const int on = 1, off = 0;
	struct timeval timeout;
	int num_timeouts = 0, max_timeouts = 5;

	fd = socket(pinfo->client_addr.sin_family, SOCK_DGRAM, 0);
	if (fd < 0) 
	{
		perror("socket");
		goto cleanup;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
	
	if (bind(fd, (const struct sockaddr *) &pinfo->server_addr, sizeof(struct sockaddr_in))) 
    {
		perror("bind");
		goto cleanup;
	}
	if (connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(struct sockaddr_in))) 
    {
		perror("connect");
		goto cleanup;
	}
	printf("connected\n");
			
	/* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr);

	do{ 
        ret = SSL_accept(ssl); 
    } while (ret == 0);

	if (ret < 0) 
	{
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), buff));
		goto cleanup;
	}

	while (1) 
	{
		/* Read the client data into our buff array */
        memset(buff, 0, sizeof(buff));

        if (SSL_read(ssl, buff, sizeof(buff)) == -1) 
        {
            fprintf(stderr, "ERROR: failed to read\n");
            goto cleanup;
        }

        /* Print to stdout any data the client sends */
        printf("Client: %s\n", buff);

        /* Write our reply into buff */
        len = strnlen(buff, sizeof(buff));

        /* Reply back to the client */
        if (SSL_write(ssl, buff, len) != len) 
        {
            fprintf(stderr, "ERROR: failed to write\n");
            goto cleanup;
        }     

        /* Check for server shutdown command */
        if (strncmp(buff, "exit", 4) == 0) 
        {
            printf("Exit command issued!\n");
            break;
        }  
	}

	SSL_shutdown(ssl);

cleanup:
	close(fd);
	free(info);
	SSL_free(ssl);
	pthread_exit( (void *) NULL );
}


int start_server(int port, char *local_address) 
{
	int fd;
	struct sockaddr_in server_addr, client_addr;
	pthread_t tid;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	struct timeval timeout;
	struct pass_info *info;
	const int on = 1, off = 0;

    char caCertLoc[] = "./../../Certificates/root-ca/root-ca.cert.pem";
    char servCertLoc[] = "./../../Certificates/server/server.cert.pem";
    char servKeyLoc[] = "./../../Certificates/server/private/server.key.pem";

	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	if (inet_pton(AF_INET, local_address, &server_addr.sin_addr) < 1) 
	{
		printf("Error and/or invalid IP address");
        exit(EXIT_FAILURE);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	THREAD_setup();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(DTLS_server_method());

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	/* Load CA certificates */
    if (SSL_CTX_load_verify_locations(ctx,caCertLoc,0) != 1) 
    {
        printf("Error loading %s, please check the file.\n", caCertLoc);
        return -1;
    }

    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(caCertLoc));

    /* Load server certificates */
    if (SSL_CTX_use_certificate_file(ctx, servCertLoc, SSL_FILETYPE_PEM) != 1) 
    {
        printf("Error loading %s, please check the file.\n", servCertLoc);
        return -1;
    }
    /* Load server Keys */
    if (SSL_CTX_use_PrivateKey_file(ctx, servKeyLoc, SSL_FILETYPE_PEM) != 1) 
    {
        printf("Error loading %s, please check the file.\n", servKeyLoc);
        return -1;
    }
   
    /* We've loaded both certificate and the key, check if they match */
    if (SSL_CTX_check_private_key(ctx) != 1) 
    {
        fprintf(stderr, "Server's certificate and the key don't match\n");
        return -1;
    }

	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

	fd = socket(server_addr.sin_family, SOCK_DGRAM, 0);
	if (fd < 0) 
	{
		perror("socket");
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));

	if (bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in))) 
	{
		perror("bind");
		return -1;
	}
	
	while (1)
	{
		memset(&client_addr, 0, sizeof(struct sockaddr_in));

		/* Create BIO */
		bio = BIO_new_dgram(fd, BIO_NOCLOSE);

		ssl = SSL_new(ctx);

		SSL_set_bio(ssl, bio, bio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
		while (DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr) <= 0);

		info = (struct pass_info*) malloc (sizeof(struct pass_info));
		memcpy(&info->server_addr, &server_addr, sizeof(struct sockaddr_in));
		memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_in));
		info->ssl = ssl;

		if (pthread_create( &tid, NULL, connection_handle, info) != 0) 
        {
			perror("pthread_create");
			return -1;
		}
	}

	THREAD_cleanup();
}

int main(int argc, char **argv)
{
	int port = 55000;
	int length = 100;
	int messagenumber = 5;
	char local_addr[20];

	memset(local_addr, 0, 20);

	argc--;
	argv++;

	while (argc >= 1) 
    {
		if	(strcmp(*argv, "-L") == 0) 
        {
			if (--argc < 1) 
                goto cmd_err;

			strncpy(local_addr, *++argv, 15);
		}
		else if	(strcmp(*argv, "-p") == 0) 
        {
			if (--argc < 1) 
                goto cmd_err;

			port = atoi(*++argv);
		}
		else if	(((*argv)[0]) == '-') 
			goto cmd_err;
		
		else 
            break;

		argc--;
		argv++;
	}

	if (argc > 1) 
        goto cmd_err;

	if(start_server(port, local_addr) == -1)
    {
        printf("Server error\n");
    }

	return 0;

cmd_err:
	fprintf(stderr, "%s\n", Usage);
	return 0;
}
