
# Creating the Intermediate CA

### Directories and Files

We are using a specific directory structure for the certificate authority(CA) to save keys, signed certificates, signing requests and revocation lists.

`$ cd intermediate-ca`
`$ mkdir certreqs certs crl newcerts private`

Some data files are needed to keep track of issued certificates, their serial numbers and revocations.

`$ touch intermediate-ca.index`
`$ echo 00 > intermediate-ca.crlnum`

The serial number should be unique for each certificate issued  by a CA. 

`$ openssl rand -hex 16 > intermediate-ca.serial`

Now we have to create a configure file. The configure file for "intermediate-ca" can be found on ../config/intermediate-ca.cnf.
All the details required to create a certificate will be present in root-ca.cnf file. Those informations can be changed by updating the intermediate-ca.cnf file.

To use the intermediate-ca.cnf as the default configuration file for creating Intermediate CA:

`$ export OPENSSL_CONF=../config/intermediate-ca.cnf`

### Generate CSR and new Key

To create private key for Intermediate CA and a certificate Signing Request for the same, use the following command:

`$ openssl req -new -out intermediate-ca.csr`

We can use **-passout pass:YourPassword** to set password of the key using the command line.

`$ openssl req -new -out intermediate-ca.csr -passout pass:1234`

The private key will be stores in private/intermediate-ca.key and the CSR will be named as intermediate-ca.csr.

After successfully creating the intermediate CSR, copy the CSR to Root CA for signing.

`$ cp intermediate-ca.csr ../root-ca/certreqs/`

## Sign the Intermediate CA with the Root CA  

Change the working directory to root-ca:

`$ cd ../root-ca/`

Export configuration of Root CA, so that we can use it to sign the intermediate CA.

`$ export OPENSSL_CONF=../config/root-ca.cnf`

Sign the intermediate CA with the Root CA

`$ openssl rand -hex 16 > root-ca.serial`
`$ openssl ca -in certreqs/intermediate-ca.csr -out certs/intermediate-ca.cert.pem -extensions intermed-ca_ext`

We can use **-passin pass:YourPassword** to set password of the key using the command line.

`$ openssl ca -in certreqs/intermediate-ca.csr -out certs/intermediate-ca.cert.pem -extensions intermed-ca_ext -passin pass:1234`

Verify the signed certificate

`$ openssl verify -verbose -CAfile root-ca.cert.pem certs/intermediate-ca.cert.pem`

The output of the above command should return **OK**

After that, put the signed certificate to the right place where it belongs i.e. intermediate-ca/

`$ cp certs/intermediate-ca.cert.pem ../intermediate-ca/`

# Creating Certificate Chain

When signing certificate using Intermediate CA, then we have to create certificate chain.
It is a list of certificate from the Root CA to Intermediate CA. 
In other words, the chain of trust refers to your TLS/SSL certificate and how it is linked back to a trusted Certificate Authority. In order for an TLS certificate to be trusted, it has to be traceable back to the trust root it was signed off, meaning all certificates in the chain—server, intermediate and root—need to be properly trusted.

So, to create a certificate chain use the following command:
First create a directory in the **Certificates** directory
`mkdir chain_cert`
`cd chain_cert`
`$ cat ../intermediate-ca/intermediate-ca.cert.pem ../root-ca/root-ca.cert.pem > chain.cert.pem`

On the server and client application, we have to pass 3 parameters:

* Certificate chain
* Server/Client certificate
* Server/Client private key 

# Revocation List

Change back to the intermediate directory

`$ cd ../intermediate-ca/`

Export configuration of Intermediate CA

`$ export OPENSSL_CONF=../config/intermediate-ca.cnf`

Create the Intermediate CA certificate revocation list (CRL) using the openssl command

`$ openssl ca -gencrl -out crl/intermed-ca.crl`

# Reference

https://roll.urown.net/ca/ca_intermed_setup.html#id6
