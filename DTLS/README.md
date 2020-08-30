Datagram Transmission Layer Security (DTLS)
==========================================

This repository contains simple examples, written in C, which demonstrates usage of 
UDP for for unreliable / connection less communication between two processes running 
on single device or running on different devices with DTLS security enabled.

# Table of Contents
1. DTLS Introduction
2. Blocking UDP Server and Blocking UDP Client with DTLS Security
3. Non-blocking UDP Server and Non-blocking UDP Client with DTLS Security
4. Compilation Steps

## 1. DTLS Introduction

The basic design philosophy of DTLS is to construct "TLS over
datagram transport".  The reason that TLS cannot be used directly in
datagram environments is simply that packets may be lost or reordered.
TLS has no internal facilities to handle this kind of unreliability; 
therefore, TLS implementations break when rehosted on datagram transport.
The purpose of DTLS is to make only the minimal changes to TLS required 
to fix this problem.  To the greatest extent possible, DTLS is identical 
to TLS.  Whenever we need to invent new mechanisms, we attempt to do so 
in such a way that preserves the style of TLS.

DTLS is used over User Datagram Protocol (UDP) protocol.


## 2. Blocking UDP Server and Blocking UDP Client with DTLS Security

Sockets can be in either blocking or non-blocking mode. By default, sockets 
are in blocking mode. In blocking mode, the send(), connect(), recv() and accept() 
socket API calls will block indefinitely until the requested action has been performed.

For example, when you call recv() to read from a stream, control isn't returned to 
your program until at least one byte of data is read from the remote site. 
This process of waiting for data to appear is referred to as "blocking". 

To secure the communication over UDP using x509 certificates and Pre-Shared Keys (PSK), 
APIs are used from openssl library.

## 3. Non-blocking UDP Server and Non-blocking UDP Client with DTLS Security

In non-blocking mode, blocking socket APIs do not block instead return immediately if
there is nothing pending.
We can flag these sockets as non-blocking by using fcntl() system call.
```
fcntl(sockfd, F_SETFL, O_NONBLOCK);
```

To secure the communication over UDP using x509 certificates and Pre-Shared Keys (PSK), 
APIs are used from openssl library.

## 4. Compilation Steps

- To compile DTLS examples
```
make dtls
```

- To compile DTLS x509 Blocking examples
```
make dtls_x509_blocking
```

- To compile DTLS PSK Blocking examples
```
make dtls_psk_blocking
```

- To compile DTLS x509 Non-Blocking examples
```
make dtls_x509_non_blocking
```

- To compile DTLS PSK Non-Blocking examples
```
make dtls_psk_non_blocking
```

- To remove executables
```
make clean
```


# References

- RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
- RFC 6347: Datagram Transport Layer Security (DTLS) Version 1.2

