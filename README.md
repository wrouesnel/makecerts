[![Build and Test](https://github.com/wrouesnel/poller_exporter/actions/workflows/integration.yml/badge.svg)](https://github.com/wrouesnel/makecerts/actions/workflows/integration.yml)
[![Release](https://github.com/wrouesnel/poller_exporter/actions/workflows/release.yml/badge.svg)](https://github.com/wrouesnel/makecerts/actions/workflows/release.yml)
[![Container Build](https://github.com/wrouesnel/poller_exporter/actions/workflows/container.yml/badge.svg)](https://github.com/wrouesnel/makecerts/actions/workflows/container.yml)
[![Coverage Status](https://coveralls.io/repos/github/wrouesnel/poller_exporter/badge.svg?branch=main)](https://coveralls.io/github/wrouesnel/makecerts?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/wrouesnel/makecerts)](https://goreportcard.com/report/github.com/wrouesnel/makecerts)

# makecerts #

Simple tool to generate a certificate authority and a directory of certificates
for a list of hosts.

Developed for testing SSL/TLS configuration of services in docker-compose.

## Usage

Basic usage is to invoke the tool with a list of hosts:

```bash
$ makecerts certificate host1 host2 host3
```

Multiple types of operation can be invoked:

```bash
$ makecerts certificate host1 -- sign host2 -- request host3
```

Operations can also be supplied via stdin, in which case the format follows the
command line format but is line delimited - i.e.

```bash
$ makecerts << EOF
certificate
host1
host2
host3
EOF
```

Output will be similar to the following:

```bash
1.6959800256860955e+09	info	makecerts/makecerts.go:287	CA Certificate filenames	{"ca_certificate_filename": "localhost.ca.crt", "ca_key_filename": "localhost.ca.pem"}
1.6959800256871305e+09	info	makecerts/makecerts.go:293	Successfully loaded existing certificates from previous session	{"ca_certificate_filename": "localhost.ca.crt", "ca_key_filename": "localhost.ca.pem"}
1.6959800256871965e+09	info	makecerts/makecerts.go:374	Generating certificates.
1.6959800256872172e+09	info	makecerts/makecerts.go:377	Generating certificate	{"hostname": "host1"}
1.69598002568737e+09	info	makecerts/makecerts.go:377	Generating certificate	{"hostname": "host2"}
1.6959800256874237e+09	info	makecerts/makecerts.go:377	Generating certificate	{"hostname": "host3"}
1.6959800256874685e+09	info	makecerts/makecerts.go:406	Outputing requested certificates
1.6959800256875002e+09	info	makecerts/makecerts.go:408	Signing certificate	{"common_name": "localhost"}
1.6959800256880586e+09	info	makecerts/makecerts.go:418	Outputting certificate	{"certificate_filename": "localhost.crt", "key_filename": "localhost.pem"}
1.695980025688253e+09	info	makecerts/makecerts.go:408	Signing certificate	{"common_name": "host1"}
1.6959800256886046e+09	info	makecerts/makecerts.go:418	Outputting certificate	{"certificate_filename": "host1.crt", "key_filename": "host1.pem"}
1.6959800256887555e+09	info	makecerts/makecerts.go:408	Signing certificate	{"common_name": "host2"}
1.6959800256891067e+09	info	makecerts/makecerts.go:418	Outputting certificate	{"certificate_filename": "host2.crt", "key_filename": "host2.pem"}
1.695980025689263e+09	info	makecerts/makecerts.go:408	Signing certificate	{"common_name": "host3"}
1.695980025689601e+09	info	makecerts/makecerts.go:418	Outputting certificate	{"certificate_filename": "host3.crt", "key_filename": "host3.pem"}
1.6959800256897435e+09	info	makecerts/makecerts.go:428	Certificate generation finished

$ ls -l
total 50K
-rw-r--r-- 1 will will 709 Sep 29 19:34 host1.crt
-rw------- 1 will will 227 Sep 29 19:34 host1.pem
-rw-r--r-- 1 will will 709 Sep 29 19:34 host2.crt
-rw------- 1 will will 227 Sep 29 19:34 host2.pem
-rw-r--r-- 1 will will 709 Sep 29 19:34 host3.crt
-rw------- 1 will will 227 Sep 29 19:34 host3.pem
-rw-r--r-- 1 will will 765 Sep 29 19:34 localhost.ca.crt
-rw------- 1 will will 227 Sep 29 19:34 localhost.ca.pem
-rw-r--r-- 1 will will 765 Sep 29 19:34 localhost.crt
-rw------- 1 will will 227 Sep 29 19:34 localhost.pem
```

This generates a CA certificate for localhost, and a number of certificates with the specified hostname.
The CommonName is set to the first name provided, additional names can be provided separated by commas to add 
SANs. SAN names are auto-recognized as hostnames, IP addresses or emails - e.g.

### Adding Subject Alternative Names of different types 

```
$ makecerts --host some.name,127.0.0.1,my@email
```

Will create a certificate with the following:

```
$ openssl x509 -in some.name.crt -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1695980668861366293 (0x1789556ec1694015)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = NoCountry, O = NoOrg, OU = NoOrgUnit, CN = localhost
        Validity
            Not Before: Sep 29 09:44:28 2023 GMT
            Not After : Sep  5 09:44:28 2122 GMT
        Subject: C = NoCountry, O = NoOrg, OU = NoOrgUnit, CN = some.name
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:89:b3:b4:60:1e:fb:a5:40:c8:48:43:a3:d0:a2:
                    11:0e:c9:fa:16:42:a4:14:a2:1a:d7:16:4b:ea:cc:
                    e3:40:45:d8:3f:2b:1a:8d:fc:50:23:61:7f:63:7e:
                    e9:b7:7b:d1:f7:30:6a:98:73:49:35:26:a0:8f:47:
                    1e:95:fd:2d:9f
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Alternative Name: 
                DNS:some.name, email:my@email, IP Address:127.0.0.1
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:43:cf:49:50:de:9e:bd:97:c0:fa:01:ec:7c:96:
        cb:5b:75:3b:24:f3:12:5f:0e:49:77:12:ec:9e:ab:61:39:10:
        02:20:02:1d:6c:80:13:01:c9:0d:90:cf:76:b0:20:95:45:2b:
        ff:5a:5c:cd:7a:cb:49:8c:34:91:14:56:e6:a6:57:1a
```

### Generate Certificate Requests

You can request certificate requests be generated. A Certificate Authority will not be generated in this case, but
the normal certificate rules otherwise apply.

```
$ makecerts --request host1 --request host2
```

Note: an invocation solely asking for certificate requests will **not** cause the generation or loading of a new CA certificate
since one is not needed. Pass `--generate-ca` if you want to force one to be created regardless (this won't overwrite anything)

### Signing Certificate Requests

You can sign a certificate request by parsing the file name as part of the `--sign` parameter.

```
$ makecerts --sign host1 --sign host2
```

The usual rules of certificate generation apply: if a CA does not exist then one will be created to sign the requests.
Certificate requests will have all extensions naively respected - this is a command line testing utility not a full
policy engine.

## Hacking

The build systme is based on Mage. `go run mage.go` will compile and produce a
list of targets. `go run mage.go binary` will build a binary for your platform
and symlink it from the root directory.
