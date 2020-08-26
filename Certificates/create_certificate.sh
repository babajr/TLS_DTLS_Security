#!/bin/bash

print_usage()
{
    echo "This script creates Root CA, Intermediate CA, Server and Client certificates."
    echo "By default Root CA is enabled and the other certificated will be signed 
         by the Root CA."
    echo "-i: Enable Intermediate Certificate Authority. If the user want to sign the server/client 
         certificates by the Intermediate CA, then use this option."
    echo "-d: Deletes all the files created by this script."
}

#Flag to enable Intermediate CA
enable_intermediate=0

create_root_ca()
{
    cd root-ca
    mkdir certreqs certs crl newcerts private
    touch root-ca.index
    echo 00 > root-ca.crlnum
    openssl rand -hex 16 > root-ca.serial
    cp ../config/root-ca.cnf .
    export OPENSSL_CONF=./root-ca.cnf
    openssl req -new -out root-ca.csr -passout pass:1234
    openssl rand -hex 16 > root-ca.serial
    # The option "-batch" is used to ignore the prompt and provide "yes" option to the script,
    # without disturbing the script. 
    openssl ca -batch -selfsign -in root-ca.csr -out root-ca.cert.pem -extensions root-ca_ext -passin pass:1234
    verify_root=`openssl verify -verbose -CAfile root-ca.cert.pem root-ca.cert.pem`
    if [ "$verify_root" != "root-ca.cert.pem: OK" ]; 
    then
        echo "ERROR: Root Certificate Authority verification failed" 
        exit
    else
        echo "SUCCESS: Root Certificate Authority verified"
    fi

    # back to root directory 
    cd ..
}

create_intermediate_ca()
{
    cd intermediate-ca
    mkdir certreqs certs crl newcerts private
    touch intermediate-ca.index
    echo 00 > intermediate-ca.crlnum
    openssl rand -hex 16 > intermediate-ca.serial
    cp ../config/intermediate-ca.cnf .
    export OPENSSL_CONF=./intermediate-ca.cnf
    openssl req -new -out intermediate-ca.csr -passout pass:1234
    cp intermediate-ca.csr ../root-ca/certreqs/

    cd ../root-ca/
    export OPENSSL_CONF=./root-ca.cnf
    openssl rand -hex 16 > root-ca.serial
    openssl ca -batch -in certreqs/intermediate-ca.csr -out certs/intermediate-ca.cert.pem -extensions intermed-ca_ext -passin pass:1234
    
    verify_intermediate=`openssl verify -verbose -CAfile root-ca.cert.pem certs/intermediate-ca.cert.pem`
    
    if [ "$verify_intermediate" != "certs/intermediate-ca.cert.pem: OK" ]; 
    then
        echo "ERROR: Intermediate Certificate Authority verification failed" 
        exit
    else
        echo "SUCCESS: Intermediate Certificate Authority verified"
    fi
    
    cp certs/intermediate-ca.cert.pem ../intermediate-ca/

    cd ../intermediate-ca/

    mkdir ../chain_cert
    #creating CA chain
    cat intermediate-ca.cert.pem ../root-ca/root-ca.cert.pem > ../chain_cert/chain.cert.pem

    export OPENSSL_CONF=./intermediate-ca.cnf
    openssl ca -gencrl -out crl/intermed-ca.crl -passin pass:1234

    # back to root directory 
    cd ..
}

create_server()
{
    cd server
    mkdir private

    cp ../config/server.cnf .
    export OPENSSL_CONF=./server.cnf

    openssl req -new -out server.csr

    #sign the server certificate using Intermediate if selected
    if [ $enable_intermediate = 1 ]; 
    then
        cp server.csr ../intermediate-ca/certreqs/
        cd ../intermediate-ca/
        export OPENSSL_CONF=./intermediate-ca.cnf
        openssl rand -hex 16 > intermediate-ca.serial
        openssl ca -batch -in certreqs/server.csr -out certs/server.cert.pem -extensions server_ext -passin pass:1234
        
        verify_server=`openssl verify -verbose -CAfile ../chain_cert/chain.cert.pem certs/server.cert.pem`
        if [ "$verify_server" != "certs/server.cert.pem: OK" ]; 
        then
            echo "ERROR: Server Certificate verification failed" 
            exit
        else
            echo "SUCCESS: Server Certificate verified"
        fi
    else
        
        cp server.csr ../root-ca/certreqs/
        cd ../root-ca/
        export OPENSSL_CONF=./root-ca.cnf
        openssl rand -hex 16 > root-ca.serial
        openssl ca -batch -in certreqs/server.csr -out certs/server.cert.pem -extensions server_ext -passin pass:1234
        
        verify_server=`openssl verify -verbose -CAfile root-ca.cert.pem certs/server.cert.pem`
        if [ "$verify_server" != "certs/server.cert.pem: OK" ]; 
        then
            echo "ERROR: Server Certificate verification failed" 
            exit
        else
            echo "SUCCESS: Server Certificate verified"
        fi
    fi

    cp certs/server.cert.pem ../server/

    # back to root directory 
    cd ..
}

create_client()
{
    cd client
    mkdir private

    cp ../config/client.cnf .
    export OPENSSL_CONF=./client.cnf

    openssl req -new -out client.csr

    #sign the client certificate using Intermediate if selected
    if [ $enable_intermediate = 1 ]; 
    then
        cp client.csr ../intermediate-ca/certreqs/
        cd ../intermediate-ca/
        export OPENSSL_CONF=./intermediate-ca.cnf
        openssl rand -hex 16 > intermediate-ca.serial
        openssl ca -batch -in certreqs/client.csr -out certs/client.cert.pem -extensions client_ext -passin pass:1234
        
        verify_client=`openssl verify -verbose -CAfile ../chain_cert/chain.cert.pem certs/client.cert.pem`
        
        if [ "$verify_client" != "certs/client.cert.pem: OK" ]; 
        then
            echo "ERROR: Client Certificate verification failed" 
            exit
        else
            echo "SUCCESS: Client Certificate verified"
        fi
    else
        
        cp client.csr ../root-ca/certreqs/
        cd ../root-ca/
        export OPENSSL_CONF=./root-ca.cnf
        openssl rand -hex 16 > root-ca.serial
        openssl ca -batch -in certreqs/client.csr -out certs/client.cert.pem -extensions client_ext -passin pass:1234
        
        verify_client=`openssl verify -verbose -CAfile root-ca.cert.pem certs/client.cert.pem`
        if [ "$verify_client" != "certs/client.cert.pem: OK" ]; 
        then
            echo "ERROR: Client Certificate verification failed" 
            exit
        else
            echo "SUCCESS: Client Certificate verified"
        fi
    fi

    cp certs/client.cert.pem ../client/

    # back to root directory 
    cd ..
}

delete_files()
{
    #First copy the README.md to a temparory location and then delete all file and then copy
    #back the README.md from temparory location to the current.
    mkdir /tmp/cert_readme

    cp ./root-ca/README.md /tmp/cert_readme
    rm -r ./root-ca/*
    mv /tmp/cert_readme/README.md ./root-ca/

    if [ $enable_intermediate = 1 ]; 
    then
        cp ./intermediate-ca/README.md /tmp/cert_readme
        rm -r ./intermediate-ca/*
        mv /tmp/cert_readme/README.md ./intermediate-ca/

        rm -r chain_cert
    fi

    cp ./server/README.md /tmp/cert_readme
    rm -r ./server/*
    mv /tmp/cert_readme/README.md ./server/

    cp ./client/README.md /tmp/cert_readme
    rm -r ./client/*
    mv /tmp/cert_readme/README.md ./client/

    rm -r /tmp/cert_readme
}

while getopts di flag
do
    case "${flag}" in
        d) delete_files
            echo "Deleted all files"
            exit;;
        i) enable_intermediate=1;;
        *) print_usage
            exit;;
    esac
done

create_root_ca

if [ $enable_intermediate = 1 ]; 
then
    create_intermediate_ca
fi

create_server
create_client


