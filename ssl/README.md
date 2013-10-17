SSL INTERCEPTOR
===============

NOTES
-----

* Generate server certificate/keys (password can be anything, will be stripped from the cert)

```
cd keys && ./keygen.sh && cd -
```

* Does NOT follow HTTP redirects and other fancy things

* Connect with SSL:

```
openssl s_client -connect localhost:4443
```
