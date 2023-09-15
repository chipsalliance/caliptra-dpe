# Licensed under the Apache-2.0 license

#!/bin/sh
set -ex

openssl ecparam -name prime256v1 -genkey -noout -out key_256.pem
openssl req -new -key key_256.pem -x509 -nodes -days 365 -out cert_256.pem -addext keyUsage=keyCertSign
openssl ec -in key_256.pem -outform DER -out key_256.der
openssl x509 -in cert_256.pem -outform DER -out cert_256.der

openssl ecparam -name secp384r1 -genkey -noout -out key_384.pem
openssl req -new -key key_384.pem -x509 -nodes -days 365 -out cert_384.pem -addext keyUsage=keyCertSign
openssl ec -in key_384.pem -outform DER -out key_384.der
openssl x509 -in cert_384.pem -outform DER -out cert_384.der