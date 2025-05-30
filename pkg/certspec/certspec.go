package certspec

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/samber/lo"
	"github.com/wrouesnel/certutils"
)

const usage = "usage"
const extusage = "extusage"
const ca = "ca"
const maxpathlen = "maxpathlen"
const template = "template"
const name = "name"

const cert = "cert"
const key = "key"
const csr = "csr"

var keyUsageMap = map[string]string{}    //nolint:gochecknoglobals
var extKeyUsageMap = map[string]string{} //nolint:gochecknoglobals

var usageList = []string{}    //nolint:gochecknoglobals
var extUsageList = []string{} //nolint:gochecknoglobals

var (
	ErrUnknownParameter = errors.New("unknown parameter")
)

func init() {
	// Setup the lower case lookup tables
	for _, value := range certutils.ListKeyUsage() {
		usageList = append(usageList, strings.ToLower(value))
		keyUsageMap[strings.ToLower(value)] = value
	}

	for _, value := range certutils.ListExtKeyUsage() {
		extUsageList = append(extUsageList, strings.ToLower(value))
		extKeyUsageMap[strings.ToLower(value)] = value
	}
}

func Usages() []string {
	return usageList[:]
}

func ExtUsages() []string {
	return extUsageList[:]
}

type CertSpecification struct {
	Hosts []string

	// CommonName is the explicitly set common name.
	CommonName string

	KeyUsage            x509.KeyUsage
	ExtKeyUsage         []x509.ExtKeyUsage
	IsCa                bool
	MaxPathLen          int
	CertificateTemplate string

	// Certificate file is the name of the certificate
	CertificateFile string
	// KeyFile is the name of the key file
	KeyFile string
	// CSRFile is the name of the CSR
	CSRFile string
}

func (c *CertSpecification) UnmarshalText(text []byte) error {
	line := string(text)
	sans, options, _ := strings.Cut(line, "?")

	c.Hosts = make([]string, 0)
	c.KeyUsage = 0
	c.ExtKeyUsage = make([]x509.ExtKeyUsage, 0)
	c.IsCa = false
	c.MaxPathLen = 0

	for _, san := range strings.Split(sans, ",") {
		c.Hosts = append(c.Hosts, san)
	}

	query, err := url.ParseQuery(options)
	if err != nil {
		return err
	}

	if query.Has(usage) {
		for _, value := range query[usage] {
			for _, split := range strings.Split(value, ",") {
				lookup, found := keyUsageMap[split]
				if !found {
					return errors.Join(ErrUnknownParameter, fmt.Errorf("key usage %s unrecognized", lookup))
				}
				c.KeyUsage |= lo.Must(certutils.ParseKeyUsage(lookup))
			}
		}
	}

	if query.Has(extusage) {
		for _, value := range query[extusage] {
			for _, joined := range strings.Split(value, ",") {
				lookup, found := extKeyUsageMap[joined]
				if !found {
					return errors.Join(ErrUnknownParameter, fmt.Errorf("extended key usage %s unrecognized", value))
				}
				c.ExtKeyUsage = append(c.ExtKeyUsage, lo.Must(certutils.ParseExtKeyUsage(lookup)))
			}
		}
	}

	if query.Has(ca) {
		value := query.Get(ca)
		c.IsCa, err = strconv.ParseBool(value)
		if err != nil {
			return errors.Join(ErrUnknownParameter, fmt.Errorf("ca parameter %s unrecognized", value))
		}
	}

	if query.Has(maxpathlen) {
		value := query.Get(maxpathlen)
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return errors.Join(ErrUnknownParameter, fmt.Errorf("maxpathlen could not be parsed: %s", value))
		}
		c.MaxPathLen = int(parsed) //nolint:gosec
	}

	if query.Has(name) {
		value := query.Get(name)
		c.CommonName = value
	}

	if query.Has(template) {
		value := query.Get(template)
		c.CertificateTemplate = value
	}

	c.CertificateFile = query.Get(cert)
	c.KeyFile = query.Get(key)
	c.CSRFile = query.Get(csr)

	return nil
}
