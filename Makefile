FLAGS = -g -o
DTLS_PSK = DTLS/psk
DTLS_X509 = DTLS/x509_certs
TLS_PSK = TLS/psk
TLS_X509 = TLS/x509_certs
LIBS = -lssl -lcrypto -lpthread

all: dtls tls

tls: tls_x509_blocking tls_psk_blocking

tls_x509_blocking: $(TLS_X509)/tls-client.o $(TLS_X509)/tls-server.o

$(TLS_X509)/tls-client.o: $(TLS_X509)/tls-client.c
	gcc $(FLAGS) $(TLS_X509)/client $(TLS_X509)/tls-client.c $(LIBS)

$(TLS_X509)/tls-server.o: $(TLS_X509)/tls-server.c
	gcc $(FLAGS) $(TLS_X509)/server $(TLS_X509)/tls-server.c $(LIBS)

tls_psk_blocking: $(TLS_PSK)/tls-client.o $(TLS_PSK)/tls-server.o

$(TLS_PSK)/tls-client.o: $(TLS_PSK)/psk-client.c
	gcc $(FLAGS) $(TLS_PSK)/client $(TLS_PSK)/psk-client.c $(LIBS)

$(TLS_PSK)/tls-server.o: $(TLS_PSK)/psk-server.c
	gcc $(FLAGS) $(TLS_PSK)/server $(TLS_PSK)/psk-server.c $(LIBS)


dtls: dtls_x509_blocking dtls_psk_blocking

dtls_x509_blocking: $(DTLS_X509)/dtls-client.o $(DTLS_X509)/dtls-server.o

$(DTLS_X509)/dtls-client.o: $(DTLS_X509)/dtls-client.c
	gcc $(FLAGS) $(DTLS_X509)/client $(DTLS_X509)/dtls-client.c $(LIBS)

$(DTLS_X509)/dtls-server.o: $(DTLS_X509)/dtls-server.c
	gcc $(FLAGS) $(DTLS_X509)/server $(DTLS_X509)/dtls-server.c $(LIBS)

dtls_psk_blocking: $(DTLS_PSK)/dtls-client.o $(DTLS_PSK)/dtls-server.o

$(DTLS_PSK)/dtls-client.o: $(DTLS_PSK)/psk-client.c
	gcc $(FLAGS) $(DTLS_PSK)/client $(DTLS_PSK)/psk-client.c $(LIBS)

$(DTLS_PSK)/dtls-server.o: $(DTLS_PSK)/psk-server.c
	gcc $(FLAGS) $(DTLS_PSK)/server $(DTLS_PSK)/psk-server.c $(LIBS)


clean:
	rm -f $(TLS_X509)/client
	rm -f $(TLS_X509)/server
	rm -f $(DTLS_X509)/client
	rm -f $(DTLS_X509)/server
	rm -f $(TLS_PSK)/client
	rm -f $(TLS_PSK)/server
	rm -f $(DTLS_PSK)/client
	rm -f $(DTLS_PSK)/server
