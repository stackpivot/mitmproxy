SSL INTERCEPTOR
===============

NOTES
-----

* Generate server certificate/keys (password can be anything, will be stripped from the cert)

```
cd keys && ./keygen.sh && cd -
```

* see README.md for HTTP interceptor as it applies also to SSL

* Connect with SSL:

```
openssl s_client -connect localhost:4443
```
