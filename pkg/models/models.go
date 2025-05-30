package models

import "crypto/x509"

// X509CertificateAndKey holds the tuple of certificate data.
type X509CertificateAndKey struct {
	Cert *x509.Certificate
	Key  interface{}
}
