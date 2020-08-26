
# Creating the Root CA

### Directories and Files

We are using a specific directory structure for the certificate authority(CA) to save keys, signed certificates, signing requests and revocation lists.

`$ cd root-ca`
`$ mkdir certreqs certs crl newcerts private`

Some data files are needed to keep track of issued certificates, their serial numbers and revocations.

`$ touch root-ca.index`
`$ echo 00 > root-ca.crlnum`

The serial number should be unique for each certificate issued  by a CA. 

`$ openssl rand -hex 16 > root-ca.serial`

Now we have to create a configure file. The configure file for "root-ca" can be found on ../config/root-ca.cnf.
All the details required to create a certificate will be present in root-ca.cnf file. Those informations can be changed by updating the root-ca.cnf file.

To use the root-ca.cnf as the default configuration file for creating Root CA:

`$ export OPENSSL_CONF=../config/root-ca.cnf`

### Generate CSR and new Key

To create private key for Root CA and a certificate Signing Request for the same, use the following command:

`$ openssl req -new -out root-ca.csr`

We can use **-passout pass:YourPassword** to set password of the key using the command line.

Ex: `$ openssl req -new -out root-ca.csr -passout pass:1234`

The private key will be stores in private/root-ca.key and the CSR will be named as root-ca.csr.

### Self-Signing the Root CA

The Root CA will be signing its own CSR (it is the only CA available and it will be used to sign other CAs).

`$ openssl rand -hex 16 > root-ca.serial`
`$ openssl ca -selfsign -in root-ca.csr -out root-ca.cert.pem -extensions root-ca_ext` 

To enter password through command line, use **-passin pass:YourPassword**

`$ openssl ca -selfsign -in root-ca.csr -out root-ca.cert.pem -extensions root-ca_ext -passin pass:1234` 

To verify the certificate, run the following command:

`$ openssl verify -verbose -CAfile root-ca.cert.pem root-ca.cert.pem`

The output of the above command should return **OK**

This certificate (root-ca.cert.pem) will be used to sign all the other intermediate CAs from now on.

# Reference

https://roll.urown.net/ca/ca_root_setup.html
