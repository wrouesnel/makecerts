package models

// CertificateFilenameConfig carries the filename configuration for emitting certificates
type CertificateFilenameConfig struct {
	CACertName string `help:"CA Certificate Filename"`
	CAKeyName  string `help:"CA Key Filename"`
	CACSRName  string `help:"CA CSR Filename"`

	CaPrefix string `help:"Prefix to be added to the filename of CA certificates and CSRS" default:""`
	CaSuffix string `help:"Suffix to be added to filename of CA certificates and CSRs" default:"ca"`

	NamePrefix string `help:"Filename prefix to add to certificates. A dot separator is added automatically."`
	NameSuffix string `help:"Filename suffix to add to certificates before extension. A dot separator is added automatically."`

	CertFileExt    string `help:"Certificate file extension to add to public keys" default:"crt"`
	KeyFileExt     string `help:"Certificate file extension to add to private keys" default:"key"`
	RequestFileExt string `help:"Certificate Request file extension" default:"csr"`
}
