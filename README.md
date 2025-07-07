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

This generates a CA certificate for localhost, and a number of certificates with the specified hostname.
The CommonName is set to the first name provided, additional names can be provided separated by commas to add 
SANs. SAN names are auto-recognized as hostnames, IP addresses or emails - e.g.

The special command `ca` can be used when you want to simply generate a CA in place for later use  without generating 
any certificates. This command takes no options, and multiple uses will be ignored.

```bash
$ makecerts ca
```

### Certificate Options

When generating certificates or CSRs, a number of options can be specified in URL-encoded syntax format:

| Name        | Description                                                                                                                                                                                                                                                                                                                                             |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `usage`     | Key Usage: <br/>`digitalsignature` <br/>`contentcommitment` <br/>`keyencipherment` <br/>`dataencipherment` <br/>`keyagreement` <br/>`certsign` <br/>`crlsign` <br/>`encipheronly` <br/>`decipheronly` <br/>Default is `digitalsignature`                                                                                                                |
| `extusage`  | Extended Key Usage: <br/>`any` <br/>`serverauth` <br/>`clientauth` <br/>`codesigning` <br/>`emailprotection` <br/>`ipsecendsystem` <br/>`ipsectunnel` <br/>`ipsecuser` <br/>`timestamping` <br/>`ocspsigning` <br/>`microsoftservergatedcrypto` <br/>`netscapeservergatedcrypto` <br/>`microsoftcommercialcodesigning` <br/>`microsoftkernelcodesigning` |
| `ca`        | Certificate Authority Basic Constraint: `true` or `false`                                                                                                                                                                                                                                                                                               |
| `maxpathlen` | Certificate Authority Max Path Length Basic Constraint                                                                                                                                                                                                                                                                                                  |
| `template`  | Microsoft ADCS enrollment certificate type (string which matches server template)                                                                                                                                                                                                                                                                       |
| `name`      | Certificate Common Name (otherwise first SAN will be used)                                                                                                                                                                                                                                                                                              |
| `cert`      | Filename or path of certificate file to read or create                                                                                                                                                                                                                                                                                                  |
| `key`       | Filename or path of private key file to read or create                                                                                                                                                                                                                                                                                                  |
| `csr`       | Filename or path of certificate signing request to read or create                                                                                                                                                                                                                                                                                       |

#### Example Usage

```bash
# Generate a CSR for a new CA
./makecerts request "issuing_ca?ca=1&maxpathlen=1&name=Test Issuing CA"
```

## Hacking



The build systme is based on Mage. `go run mage.go` will compile and produce a
list of targets. `go run mage.go binary` will build a binary for your platform
and symlink it from the root directory.
