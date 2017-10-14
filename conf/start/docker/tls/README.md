# TLS material

The files in this directory are provided as examples.  DO NOT USE THEM IN PRODUCTION.

## How?

Self signed certificate for the CA
```
openssl genrsa -out zentral_ca.key 2048
openssl req -x509 -new -nodes -key zentral_ca.key -sha256 -days 3650 -out zentral_ca.crt
```

Then, for each service:
```
openssl genrsa -out zentral.key 2048
openssl req -new -key zentral.key -out zentral.csr
openssl x509 -req -in zentral.csr -CA zentral_ca.crt -CAkey zentral_ca.key -CAcreateserial -out zentral.crt -days 3650 -sha256
```

We add the root cert to the generated certs for nginx.

For the fullchains, we add the cert again.
