
# Steps for Creating Certificates

* Set configuration Environment variable to use appropriate config file
* Generate private key (optional: enable password) 
* Create Certificate Signing Request (CSR)
* Send the CSR to the Certificate Authority (CA) for signing
* Obtain the certificate from the CA and use it in your application

Now server/client can send the CSR to the Root CA or the Intermediate CA for signing.

# Script for Certificate Creation

There is a script provided to ease the process of creating the certificates

* To create certificates which are signed by the **Root CA**, just run the command:

    `$ ./create_certificate.sh`

* To create certificates which are signed by the **Intermediate CA**, run the command
    with the option **-i**:

    `$ ./create_certificate.sh -i`

* To delete all files that this script has created then run the command with the following option:
  * If Intermediate CA is disabled 

  `$ ./create_certificate.sh -d`
    
  * If Intermediate CA is enables 
  
  `$ ./create_certificate.sh -d -i`

### Root CA

To create the Root CA, follow the README.md in the root-ca/ directory.

### Intermediate CA 

To create the Intermediate CA, follow the README.md in the intermediate-ca/ directory.

### Server

To create server certificate, follow the steps given in README.md in server/

### Client

To create client certificate, follow the steps given in README.md in client/





