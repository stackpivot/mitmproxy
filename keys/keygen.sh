#!/usr/bin/bash

### SSH
ssh-keygen -f ./id_rsa


### SSL
# Generate the Private Key
openssl genrsa -des3 -out server.key 1024

# Generate a Certificate Signing Request
openssl req -new -key server.key -out server.csr

# Remove Passphrase from Key
cp server.key server.key.org
openssl rsa -in server.key.org -out server.key

# Generate a Self-Signed Certificate
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
