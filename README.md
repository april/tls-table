TLS Table
---------

`tls-table.py` is a script that generates either JSON or Mediawiki output mapping the IANA code points to their names in GnuTLS, NSS, and OpenSSL.

```
$ python tls-table.py
Generate a table of cipher names from all the major library makers.

Usage: tls-table.py <output-format> [--colorize]

Valid output formats are: json, mediawiki
```

Currently,

```
$ python tls-table.py mediawiki --colorize
```
... is used to generate the table at: https://wiki.mozilla.org/Security/Server_Side_TLS#Cipher_names_correspondence_table
