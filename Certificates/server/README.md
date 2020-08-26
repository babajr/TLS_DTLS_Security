
# Creating Server Certificate

### Directories and Files

Create a directory to store all the certificates.

`$ cd server`
`$ mkdir private`

### Generating private Key and CSR

To use server as the default configuration file for creating server certificate

`$ export OPENSSL_CONF=../config/server.cnf`

Generate the private key and CSR using the command

`$ openssl req -new -out server.csr`

To enable password for server private key, open the **server.cnf** file and in **server request options** enable **encrypt_key** option.
 
We can use **-passout pass:YourPassword** to set password of the key using the command line.

`$ openssl req -new -out server.csr -passout pass:1234`

The private key will be stores in private/server.key and the CSR will be named as server.csr.

# Signing the Server Certificate

Now it is up to you to decide that who will sign the certificate, will it be the Root CA or the Intermediate CA.
Select any one and sign the peer with the same CA.

### Root CA

To get your CSR signed from the Root CA, just copy the generated CSR to the root-ca/certreq path.

`$ cp server.csr ../root-ca/certreqs/`

Change the working directory to root-ca:

`$ cd ../root-ca/`

Export configuration of Root CA, so that we can use it to sign the server certificate.

`$ export OPENSSL_CONF=../config/root-ca.cnf`

Sign the server with the Root CA

`$ openssl rand -hex 16 > root-ca.serial`
`$ openssl ca -in certreqs/server.csr -out certs/server.cert.pem -extensions server_ext`

We can use **-passin pass:YourPassword** to set password of the key using the command line.

`$ openssl ca -in certreqs/server.csr -out certs/server.cert.pem -extensions server_ext -passin pass:1234`

Verify the signed certificate

`$ openssl verify -verbose -CAfile root-ca.cert.pem certs/server.cert.pem`

The output of the above command should return **OK**

After that, put the signed certificate to the right place where it belongs i.e. server/ 

`$ cp certs/server.cert.pem ../server/`

### Intermediate CA

To get your CSR signed from the Intermediate CA, just copy the generated CSR to the intermediate-ca/certreq path.

`$ cp server.csr ../intermediate-ca/certreqs/`

Change the working directory to intermediate-ca:

`$ cd ../intermediate-ca/`

Export configuration of Intermediate CA, so that we can use it to sign the server certificate.

`$ export OPENSSL_CONF=../config/intermediate-ca.cnf`

Sign the server with the Intermediate CA

`$ openssl rand -hex 16 > intermediate-ca.serial`
`$ openssl ca -in certreqs/server.csr -out certs/server.cert.pem -extensions server_ext`

We can use **-passin pass:YourPassword** to set password of the key using the command line.

`$ openssl ca -in certreqs/server.csr -out certs/server.cert.pem -extensions server_ext -passin pass:1234`

Verify the signed certificate

`$ openssl verify -verbose -CAfile intermediate-ca.cert.pem certs/server.cert.pem`

The output of the above command should return **OK**

After that, put the signed certificate to the right place where it belongs i.e. server/ 

`$ cp certs/server.cert.pem ../server/`
