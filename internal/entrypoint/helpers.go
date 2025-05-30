package entrypoint

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"time"
)

// Version is set during build to the current git commitish.
var Version = "development" //nolint:gochecknoglobals

// loadCSR generates a certificate from a CertificateRequest.
func loadCSR(csr *x509.CertificateRequest, serialNumber int64, notBefore time.Time, notAfter time.Time) (x509.Certificate, error) {
	if csr == nil {
		return x509.Certificate{}, ErrNilCSR
	}
	template := x509.Certificate{
		SerialNumber:       big.NewInt(serialNumber),
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		Subject:            csr.Subject,
		ExtraExtensions:    csr.Extensions,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		URIs:               csr.URIs,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
	}
	return template, nil
}

// makeCert generates a certificate for the given hosts.
func makeCert(serialNumber int64, cAttr string, oAttr string, ouAttr string, emails []string, notBefore time.Time, notAfter time.Time, hosts string) x509.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{},
			Organization:       []string{},
			OrganizationalUnit: []string{},
			CommonName:         "",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Use the first host fragment as the CN
	allHosts := strings.Split(hosts, ",")
	if len(allHosts) > 0 {
		template.Subject.CommonName = allHosts[0]
	}
	if len(cAttr) > 0 {
		template.Subject.Country = append(template.Subject.Country, cAttr)
	}
	if len(oAttr) > 0 {
		template.Subject.Organization = append(template.Subject.Organization, oAttr)
	}
	if len(ouAttr) > 0 {
		template.Subject.OrganizationalUnit = append(template.Subject.OrganizationalUnit, ouAttr)
	}

	for _, host := range allHosts {
		if strings.Contains(host, "@") {
			emails = append(emails, host)
		} else if ip := net.ParseIP(host); ip != nil {
			// IP SAN
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			// Regular DNS SAN (the most common
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	if len(emails) > 0 {
		template.EmailAddresses = append(template.EmailAddresses, emails...)
	}

	return template
}

func WithoutPrefix(ext string, prefix string) string {
	after, _ := strings.CutPrefix(ext, prefix)
	return after
}
