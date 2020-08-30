Transmission Layer Security (TLS)
=================================

This repository contains simple examples, written in C, which demonstrates usage of 
TCP for reliable / connection oriented communication between two processes running 
on single device or running on different devices with TLS security enabled.

# Table of Contents
1. TLS Introduction
2. Blocking TCP Server and Blocking TCP Client with TLS Security
3. Non-blocking TCP Server and Non-blocking TCP Client with TLS Security
4. Compilation Steps

## 1. TLS Introduction

The primary goal of the TLS protocol is to provide privacy and data
integrity between two communicating applications.  The protocol is
composed of two layers: the TLS Record Protocol and the TLS Handshake
Protocol.  At the lowest level, layered on top of some reliable
transport protocol (e.g., TCP), is the TLS Record Protocol.

The TLS Record Protocol provides connection security that has two
basic properties:
- Private connection (Cryptography is used for data encryption)
- Reliable connection (Message Integrity Check)

The TLS Handshake Protocol, allows the server and client to authenticate
each other and to negotiate an encryption algorithm and cryptographic keys 
before the application protocol transmits or receives its first byte of
data. It provides connection security that has three basic properties:
- Peer's identity can be authenticated using asymmetric, or public key, 
cryptography
- Negotiation of a shared secret is secure
- Negotiation is reliable

TLS is the most widely deployed protocol for securing network traffic.
It is widely used for protecting Web traffic and for e-mail protocols.
The primary advantage of TLS is that it provides a transparent connection-oriented 
channel. Thus, it is easy to secure an application protocol by inserting TLS
between the application layer and the transport layer. However, TLS
must run over a reliable transport channel -- typically TCP. Therefore, 
it cannot be used to secure unreliable datagram traffic.


## 2. Blocking TCP Server and Blocking TCP Client with TLS Security

Sockets can be in either blocking or non-blocking mode. By default, sockets 
are in blocking mode. In blocking mode, the send(), connect(), recv() and accept() 
socket API calls will block indefinitely until the requested action has been performed.

For example, when you call recv() to read from a stream, control isn't returned to 
your program until at least one byte of data is read from the remote site. 
This process of waiting for data to appear is referred to as "blocking". 

To secure the communication over TCP using x509 certificates and Pre-Shared Keys (PSK), 
APIs are used from openssl library.

## 3. Non-blocking TCP Server and Non-blocking TCP Client with TLS Security

In non-blocking mode, blocking socket APIs do not block instead return immediately if
there is nothing pending.
We can flag these sockets as non-blocking by using fcntl() system call.
```
fcntl(sockfd, F_SETFL, O_NONBLOCK);
```

To secure the communication over TCP using x509 certificates and Pre-Shared Keys (PSK), 
APIs are used from openssl library.

## 4. Compilation Steps

- To compile TLS examples
```
make tls
```

- To compile TLS x509 Blocking examples
```
make tls_x509_blocking
```

- To compile TLS PSK Blocking examples
```
make tls_psk_blocking
```

- To compile TLS x509 Non-Blocking examples
```
make tls_x509_non_blocking
```

- To compile TLS PSK Non-Blocking examples
```
make tls_psk_non_blocking
```

- To remove executables
```
make clean
```


# References

- RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
- RFC 6347: Datagram Transport Layer Security Version 1.2

