# Licensed under the Apache-2.0 license

#!/bin/sh
set -ex

openssl ecparam -name prime256v1 -genkey -noout -out key_256.pem
openssl req -new -key key_256.pem -x509 -nodes -days 365000 -out cert_256.pem \
  -addext keyUsage=critical,keyCertSign \
  -subj /CN="DPE Test Alias"/
openssl ec -in key_256.pem -outform DER -out key_256.der
openssl x509 -in cert_256.pem -outform DER -out cert_256.der

openssl ecparam -name secp384r1 -genkey -noout -out key_384.pem
openssl req -new -key key_384.pem -x509 -nodes -days 365000 -out cert_384.pem \
  -addext keyUsage=critical,keyCertSign \
  -subj /CN="DPE Test Alias"/
openssl ec -in key_384.pem -outform DER -out key_384.der
openssl x509 -in cert_384.pem -outform DER -out cert_384.der

# Note: Requires OpenSSL 3.5+

# We only output the seed so the PEM file can be de-serialized by Rust Crypto's pkcs8 crate.
# You can construct everything you need from just the seed.
openssl genpkey -algorithm ML-DSA-87 -provparam ml-dsa.output_formats=bare-seed -out key_mldsa_87.pem
openssl req -new -key key_mldsa_87.pem -x509 -nodes -days 365000 -out cert_mldsa_87.pem \
  -addext keyUsage=critical,keyCertSign \
  -subj /CN="DPE Test Alias"/
openssl pkey -in key_mldsa_87.pem -outform DER -provparam ml-dsa.output_formats=seed-only -out key_mldsa_87.der
openssl x509 -in cert_mldsa_87.pem -outform DER -out cert_mldsa_87.der
