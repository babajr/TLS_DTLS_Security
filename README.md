(D)TLS Security
===============
TLS and DTLS Security using OPENSSL for LEARNING. 

# (D)TLS Applications / Examples using openssl Library

This repository contains applications, written in C, which demonstrates underlying
concepts of TLS (Transport Layer Security) and DTLS (Datagram Transport Layer Security)
security using x509 certificates and Pre-Shared Keys (PSK) using openssl library.

Each directory represent a unique topic (TLS, DTLS) with subtopics (x509, PSK) and
contains a Makefile and a simple example to understand the concept.

## TLS

This directory contains example TCP server and TCP client with TLS security enabled
that demonstrates secure TCP communication between server and client in blocking and non-blocking mode.

Kindly refer the [TLS/README.md](TLS/README.md) for further details and usage.

## DTLS

This directory contains example UDP server and UDP client with DTLS security enabled
that demonstrates UDP communication between server and client in blocking and non-blocking mode.

Kindly refer the [DTLS/README.md](DTLS/README.md) for further details and usage.

## Compilation Steps

- To compile whole project
```
make all
```

- To compile TLS examples
```
make tls
```

- To compile DTLS examples
```
make dtls
```

- To remove executables
```
make clean
```

Please refer [TLS_DTLS_Security/wireshark_captures.txt](TLS_DTLS_Security/wireshark_captures.txt)
for wireshark captures.
