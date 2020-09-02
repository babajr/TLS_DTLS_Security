FLAGS = -g -o
DTLS_PSK_BLOCKING = DTLS/psk/blocking
DTLS_PSK_NON_BLOCKING = DTLS/psk/non-blocking
DTLS_X509_BLOCKING = DTLS/x509_certs/blocking
DTLS_X509_NON_BLOCKING = DTLS/x509_certs/non-blocking
TLS_PSK_BLOCKING = TLS/psk/blocking
TLS_PSK_NON_BLOCKING = TLS/psk/non-blocking
TLS_X509_BLOCKING = TLS/x509_certs/blocking
TLS_X509_NON_BLOCKING = TLS/x509_certs/non-blocking
LIBS = -lssl -lcrypto -lpthread

all: dtls tls

tls: tls_x509_blocking tls_psk_blocking tls_x509_non_blocking tls_psk_non_blocking

tls_x509_blocking: $(TLS_X509_BLOCKING)/tls-client.o $(TLS_X509_BLOCKING)/tls-server.o

$(TLS_X509_BLOCKING)/tls-client.o: $(TLS_X509_BLOCKING)/tls-client.c
	gcc $(FLAGS) $(TLS_X509_BLOCKING)/client $(TLS_X509_BLOCKING)/tls-client.c $(LIBS)

$(TLS_X509_BLOCKING)/tls-server.o: $(TLS_X509_BLOCKING)/tls-server.c
	gcc $(FLAGS) $(TLS_X509_BLOCKING)/server $(TLS_X509_BLOCKING)/tls-server.c $(LIBS)

tls_x509_non_blocking: $(TLS_X509_NON_BLOCKING)/tls-client.o $(TLS_X509_NON_BLOCKING)/tls-server.o

$(TLS_X509_NON_BLOCKING)/tls-client.o: $(TLS_X509_NON_BLOCKING)/tls-client.c
	gcc $(FLAGS) $(TLS_X509_NON_BLOCKING)/client $(TLS_X509_NON_BLOCKING)/tls-client.c $(LIBS)

$(TLS_X509_NON_BLOCKING)/tls-server.o: $(TLS_X509_NON_BLOCKING)/tls-server.c
	gcc $(FLAGS) $(TLS_X509_NON_BLOCKING)/server $(TLS_X509_NON_BLOCKING)/tls-server.c $(LIBS)


tls_psk_blocking: $(TLS_PSK_BLOCKING)/tls-client.o $(TLS_PSK_BLOCKING)/tls-server.o

$(TLS_PSK_BLOCKING)/tls-client.o: $(TLS_PSK_BLOCKING)/psk-client.c
	gcc $(FLAGS) $(TLS_PSK_BLOCKING)/client $(TLS_PSK_BLOCKING)/psk-client.c $(LIBS)

$(TLS_PSK_BLOCKING)/tls-server.o: $(TLS_PSK_BLOCKING)/psk-server.c
	gcc $(FLAGS) $(TLS_PSK_BLOCKING)/server $(TLS_PSK_BLOCKING)/psk-server.c $(LIBS)

tls_psk_non_blocking: $(TLS_PSK_NON_BLOCKING)/tls-client.o $(TLS_PSK_NON_BLOCKING)/tls-server.o

$(TLS_PSK_NON_BLOCKING)/tls-client.o: $(TLS_PSK_NON_BLOCKING)/psk-client.c
	gcc $(FLAGS) $(TLS_PSK_NON_BLOCKING)/client $(TLS_PSK_NON_BLOCKING)/psk-client.c $(LIBS)

$(TLS_PSK_NON_BLOCKING)/tls-server.o: $(TLS_PSK_NON_BLOCKING)/psk-server.c
	gcc $(FLAGS) $(TLS_PSK_NON_BLOCKING)/server $(TLS_PSK_NON_BLOCKING)/psk-server.c $(LIBS)

dtls: dtls_x509_blocking dtls_x509_non_blocking dtls_psk_blocking dtls_psk_non_blocking

dtls_x509_blocking: $(DTLS_X509_BLOCKING)/dtls-client.o $(DTLS_X509_BLOCKING)/dtls-server.o

$(DTLS_X509_BLOCKING)/dtls-client.o: $(DTLS_X509_BLOCKING)/dtls-client.c
	gcc $(FLAGS) $(DTLS_X509_BLOCKING)/client $(DTLS_X509_BLOCKING)/dtls-client.c $(LIBS)

$(DTLS_X509_BLOCKING)/dtls-server.o: $(DTLS_X509_BLOCKING)/dtls-server.c
	gcc $(FLAGS) $(DTLS_X509_BLOCKING)/server $(DTLS_X509_BLOCKING)/dtls-server.c $(LIBS)

dtls_x509_non_blocking: $(DTLS_X509_NON_BLOCKING)/dtls-client.o $(DTLS_X509_NON_BLOCKING)/dtls-server.o

$(DTLS_X509_NON_BLOCKING)/dtls-client.o: $(DTLS_X509_NON_BLOCKING)/dtls-client.c
	gcc $(FLAGS) $(DTLS_X509_NON_BLOCKING)/client $(DTLS_X509_NON_BLOCKING)/dtls-client.c $(LIBS)

$(DTLS_X509_NON_BLOCKING)/dtls-server.o: $(DTLS_X509_NON_BLOCKING)/dtls-server.c
	gcc $(FLAGS) $(DTLS_X509_NON_BLOCKING)/server $(DTLS_X509_NON_BLOCKING)/dtls-server.c $(LIBS)

dtls_psk_blocking: $(DTLS_PSK_BLOCKING)/dtls-client.o $(DTLS_PSK_BLOCKING)/dtls-server.o

$(DTLS_PSK_BLOCKING)/dtls-client.o: $(DTLS_PSK_BLOCKING)/psk-client.c
	gcc $(FLAGS) $(DTLS_PSK_BLOCKING)/client $(DTLS_PSK_BLOCKING)/psk-client.c $(LIBS)

$(DTLS_PSK_BLOCKING)/dtls-server.o: $(DTLS_PSK_BLOCKING)/psk-server.c
	gcc $(FLAGS) $(DTLS_PSK_BLOCKING)/server $(DTLS_PSK_BLOCKING)/psk-server.c $(LIBS)

dtls_psk_non_blocking: $(DTLS_PSK_NON_BLOCKING)/dtls-client.o $(DTLS_PSK_NON_BLOCKING)/dtls-server.o

$(DTLS_PSK_NON_BLOCKING)/dtls-client.o: $(DTLS_PSK_NON_BLOCKING)/psk-client.c
	gcc $(FLAGS) $(DTLS_PSK_NON_BLOCKING)/client $(DTLS_PSK_NON_BLOCKING)/psk-client.c $(LIBS)

$(DTLS_PSK_NON_BLOCKING)/dtls-server.o: $(DTLS_PSK_NON_BLOCKING)/psk-server.c
	gcc $(FLAGS) $(DTLS_PSK_NON_BLOCKING)/server $(DTLS_PSK_NON_BLOCKING)/psk-server.c $(LIBS)


clean:
	rm -f $(TLS_X509_BLOCKING)/client
	rm -f $(TLS_X509_BLOCKING)/server
	rm -f $(TLS_X509_NON_BLOCKING)/client
	rm -f $(TLS_X509_NON_BLOCKING)/server
	rm -f $(DTLS_X509_BLOCKING)/client
	rm -f $(DTLS_X509_BLOCKING)/server
	rm -f $(DTLS_X509_NON_BLOCKING)/client
	rm -f $(DTLS_X509_NON_BLOCKING)/server
	rm -f $(TLS_PSK_BLOCKING)/client
	rm -f $(TLS_PSK_BLOCKING)/server
	rm -f $(DTLS_PSK_BLOCKING)/client
	rm -f $(DTLS_PSK_BLOCKING)/server
	rm -f $(TLS_PSK_NON_BLOCKING)/client
	rm -f $(TLS_PSK_NON_BLOCKING)/server
	rm -f $(DTLS_PSK_NON_BLOCKING)/client
	rm -f $(DTLS_PSK_NON_BLOCKING)/server
