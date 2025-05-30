package models

// CertificateFilenameConfig carries the filename configuration for emitting certificates.
type CertificateFilenameConfig struct {
	CACertName string `help:"CA Certificate Filename"`
	CAKeyName  string `help:"CA Key Filename"`
	CaCSRName  string `help:"CA CSR Filename"`

	CaPrefix string `default:""   help:"Prefix to be added to the filename of CA certificates and CSRS"`
	CaSuffix string `default:"ca" help:"Suffix to be added to filename of CA certificates and CSRs"`

	NamePrefix string `help:"Filename prefix to add to certificates. A dot separator is added automatically."`
	NameSuffix string `help:"Filename suffix to add to certificates before extension. A dot separator is added automatically."`

	CertFileExt    string `default:"crt" help:"Certificate file extension to add to public keys"`
	KeyFileExt     string `default:"key" help:"Certificate file extension to add to private keys"`
	RequestFileExt string `default:"req" help:"Certificate Request file extension"`
}
