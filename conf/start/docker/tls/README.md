# TLS material

The files in this directory are provided as examples. DO NOT USE THEM IN PRODUCTION!!!

## How?

Create a self signed certificate for the CA:

```
openssl req -x509 -out zentral_ca.crt \
            -newkey rsa:2048 -nodes -keyout zentral_ca.key \
            -sha256 -days 3650 \
            -extensions ext \
            -config <(printf "[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n[dn]\nC=DE\nST=Hamburg\nL=Hamburg\nO=Zentral\nOU=IT\nCN=Zentral CA\nemailAddress=info@zentral.io\n[ext]\nbasicConstraints=CA:TRUE\nsubjectKeyIdentifier=hash\nkeyUsage=keyCertSign,cRLSign\n")
```

Create a certificate request for zentral:

```
openssl req \
        -newkey rsa:2048 -nodes -keyout zentral.key \
        -subj '/CN=zentral' \
        -out zentral.csr
```

Add the extensions and sign the request with the CA, to build the certificate:

```
openssl x509 \
        -req -in zentral.csr \
        -CA zentral_ca.crt -CAkey zentral_ca.key \
        -CAcreateserial \
        -days 3650 -sha256 \
        -extensions ext \
        -extfile <(printf "[ext]\nsubjectAltName=DNS:zentral,DNS:zentral-clicertauth\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth,emailProtection") \
        -out zentral.crt
```

Create the fullchain:
```
cat zentral.crt zentral_ca.crt > zentral_fullchain.crt
```
