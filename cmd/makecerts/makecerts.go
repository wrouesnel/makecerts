//

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/alecthomas/kong"
	"go.uber.org/zap/zapcore"

	"bufio"
	"crypto/tls"

	"go.uber.org/zap"
)

var ErrNotCertificateAuthority = errors.New("Certificate is not a CA certificate")
var ErrMultipleCSRPerFile = errors.New("Multiple certificate requests found in one file")
var ErrNoCSRFound = errors.New("No CSR request found in specified file")
var ErrNilCSR = errors.New("nil CSR passed to loadCSR")

const CertPermissions = 0644
const KeyPermissions = 0600

// Version is set during build to the current git commitish.
var Version = "development" //nolint:gochecknoglobals

// PrivateKeyGenerator wraps the function signature for RSA and Elliptic key generators.
type PrivateKeyGenerator func() (interface{}, error)

// commonNameToFilename converts a common name to a standard-ish output format.
func commonNameToFilename(cn string) string {
	outstr := cn
	outstr = strings.ReplaceAll(outstr, ".", "_")
	outstr = strings.ReplaceAll(outstr, " ", "")
	outstr = strings.ReplaceAll(outstr, "*", "STAR")
	return outstr
}

// CertData holds the tuple of certificate data.
type CertData struct {
	cert x509.Certificate
	key  interface{}
}

// EncodeToCerts signs the certificate and with the given CA certificate and returns the PEM encoded certs.
func (cd *CertData) EncodeToCerts(signing CertData) ([]byte, []byte, error) {
	derCABytes, err := x509.CreateCertificate(rand.Reader, &cd.cert, &signing.cert, publicKey(cd.key), signing.key)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck
	}
	caCertBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCABytes})
	caKeyBytes := []byte{}
	if _, ok := cd.key.(x509.Certificate); !ok {
		caKeyBytes = pem.EncodeToMemory(pemBlockForKey(cd.key))
	}
	return caCertBytes, caKeyBytes, nil
}

// EncodeToCertRequest issues a PEM encoded Certificate Signing Request.
func (cd *CertData) EncodeToCertificateSigningRequest() ([]byte, []byte, error) {
	req := &x509.CertificateRequest{
		SignatureAlgorithm: cd.cert.SignatureAlgorithm,
		PublicKeyAlgorithm: cd.cert.PublicKeyAlgorithm,
		PublicKey:          cd.cert.PublicKey,
		Subject:            cd.cert.Subject,
		Extensions:         cd.cert.Extensions,
		ExtraExtensions:    cd.cert.ExtraExtensions,
		DNSNames:           cd.cert.DNSNames,
		EmailAddresses:     cd.cert.EmailAddresses,
		IPAddresses:        cd.cert.IPAddresses,
		URIs:               cd.cert.URIs,
	}

	derCABytes, err := x509.CreateCertificateRequest(rand.Reader, req, cd.key)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck
	}
	caCertBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derCABytes})
	caKeyBytes := pem.EncodeToMemory(pemBlockForKey(cd.key))
	return caCertBytes, caKeyBytes, nil
}

// GetBasename returns the filename of the certificate.
func (cd *CertData) GetBasename() string {
	return commonNameToFilename(cd.cert.Subject.CommonName)
}

// publicKey detects the type of key and returns its PublicKey.
func publicKey(priv interface{}) interface{} {
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	case x509.Certificate:
		// For handling CSR requests
		return key.PublicKey
	default:
		return nil
	}
}

// pemBlockForKey returns a marshaled private key
// according to its type.
func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			log.Panicln("Unable to marshal ECDSA private key:", err)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// loadCSR generates a certificate from a CertificateRequest.
func loadCSR(csr *x509.CertificateRequest, serialNumber int64) (x509.Certificate, error) {
	if csr == nil {
		return x509.Certificate{}, ErrNilCSR
	}
	template := x509.Certificate{
		SerialNumber:       big.NewInt(serialNumber),
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		Subject:            csr.Subject,
		Extensions:         csr.Extensions,
		ExtraExtensions:    csr.ExtraExtensions,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		URIs:               csr.URIs,
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

//nolint:gochecknoglobals
var CLI struct {
	Version   kong.VersionFlag `help:"Show version number"`
	LogLevel  string           `help:"Logging Level" enum:"debug,info,warning,error" default:"info"`
	LogFormat string           `help:"Logging format" enum:"console,json" default:"console"`

	CommonName         string        `help:"CA Certificate Common Name, as in 'example.com'" default:"localhost"`
	Country            string        `help:"Certificate attribute: Country" default:"NoCountry"`
	Organization       string        `help:"Certificate attribute: Organization" default:"NoOrg"`
	OrganizationalUnit string        `help:"Certificate attribute: Organizational Unit" default:"NoOrgUnit"`
	Email              []string      `help:"Email addresses to be added to the certificate"`
	StartDate          time.Time     `help:"Creation date formatted as YYYY-MM-DD HH:MM:SS "`
	Duration           time.Duration `help:"Duration in days that certificate is valid for" default:"867240h"`

	CommonSans []string `help:"List of subject alt-names to add to all generated certificates"`

	RsaBits    int    `help:"Size of RSA key to generate. Ignored if --ecdsa-curve is set"`
	EcdsaCurve string `help:"ECDSA curve to use to generate a key. Valid values are P256, P384, P521" enum:"P256,P384,P521" default:"P256"`

	CaSuffix string `help:"Suffix to add to the CA certificates" default:"ca"`

	NamePrefix string `help:"Filename prefix to add to certificates. A dot separator is added automatically."`
	NameSuffix string `help:"Filename suffix to add to certificates before extension. A dot separator is added automatically."`

	CertFileExt    string `help:"Certificate file extension to add to public keys" default:"crt"`
	KeyFileExt     string `help:"Certificate file extension to add to private keys" default:"pem"`
	RequestFileExt string `help:"Certificate Request file extension" default:"csr"`

	CACertName string `help:"CA Certificate Filename"`
	CAKeyName  string `help:"CA Key Filename"`

	GenerateCA        bool `help:"Generate a new CA even if one is not required"`
	ForceCaGenerate   bool `help:"Overwrite existing CA certificates if found"`
	RequireExistingCa bool `help:"Require existing CA certificates to exist"`

	NoStdin bool `help:"Don't read hostnames from stdin'"`

	Sign    []string `help:"Certificate requests to sign with the CA certificate" sep:"none"`
	Request []string `help:"Hostname to generate certificate signing requests for" sep:"none"`
	Host    []string `help:"Hostname to generate a certificate for" sep:"none"`
}

func realMain() error { //nolint:funlen,gocognit,gocyclo,cyclop,maintidx
	vars := kong.Vars{}
	vars["version"] = Version
	kongParser, err := kong.New(&CLI, vars)
	if err != nil {
		panic(err)
	}

	_, err = kongParser.Parse(os.Args[1:])
	kongParser.FatalIfErrorf(err)

	// Configure logging
	logConfig := zap.NewProductionConfig()
	logConfig.Encoding = CLI.LogFormat
	var logLevel zapcore.Level
	if err := logLevel.UnmarshalText([]byte(CLI.LogLevel)); err != nil {
		panic(err)
	}
	logConfig.Level = zap.NewAtomicLevelAt(logLevel)

	log, err := logConfig.Build()
	if err != nil {
		panic(err)
	}

	// Replace the global logger to enable logging
	zap.ReplaceGlobals(log)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFn := context.WithCancel(context.Background())
	go func() {
		sig := <-sigCh
		log.Info("Caught signal - exiting", zap.String("signal", sig.String()))
		cancelFn()
	}()

	go func() {
		<-ctx.Done()
		log.Info("Closing stdin on signal")
		if os.Stdin != nil {
			_ = os.Stdin.Close()
		}
	}()

	// Setup a new key generation interface
	var privateKeyFn PrivateKeyGenerator

	switch CLI.EcdsaCurve {
	case "":
		privateKeyFn = func() (interface{}, error) {
			return rsa.GenerateKey(rand.Reader, CLI.RsaBits) //nolint:wrapcheck
		}
		// P224 curve is disabled because Red Hat disable it.
	case "P256":
		privateKeyFn = func() (interface{}, error) {
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //nolint:wrapcheck
		}
	case "P384":
		privateKeyFn = func() (interface{}, error) {
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) //nolint:wrapcheck
		}
	case "P521":
		privateKeyFn = func() (interface{}, error) {
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) //nolint:wrapcheck
		}
	default:
		log.Fatal("Unrecognized elliptic curve:", zap.String("ecdsa_curvse", CLI.EcdsaCurve))
	}

	mustPrivateKeyFn := func() interface{} {
		caCertKey, err := privateKeyFn()
		if err != nil {
			log.Fatal("Could not generate private key", zap.Error(err))
		}
		return caCertKey
	}

	var caCertCert CertData

	var caCertificateFilename string
	var caKeyFilename string

	if !strings.HasSuffix(CLI.NamePrefix, ".") && CLI.NamePrefix != "" {
		CLI.NamePrefix = fmt.Sprintf("%s.", CLI.NamePrefix)
	}

	if !strings.HasPrefix(CLI.NameSuffix, ".") && CLI.NameSuffix != "" {
		CLI.NameSuffix = fmt.Sprintf(".%s", CLI.NameSuffix)
	}

	if !strings.HasPrefix(CLI.CaSuffix, ".") && CLI.CaSuffix != "" {
		CLI.CaSuffix = fmt.Sprintf(".%s", CLI.CaSuffix)
	}

	if CLI.CACertName != "" {
		caCertificateFilename = CLI.CACertName
	} else {
		caCertificateFilename = fmt.Sprintf("%s%s%s%s.%s", CLI.NamePrefix, commonNameToFilename(CLI.CommonName), CLI.NameSuffix, CLI.CaSuffix, CLI.CertFileExt)
	}

	if CLI.CAKeyName != "" {
		caKeyFilename = CLI.CAKeyName
	} else {
		caKeyFilename = fmt.Sprintf("%s%s%s%s.%s", CLI.NamePrefix, commonNameToFilename(CLI.CommonName), CLI.NameSuffix, CLI.CaSuffix, CLI.KeyFileExt)
	}

	hostDescs := []string{}

	if len(CLI.Host) == 0 && len(CLI.Request) == 0 && len(CLI.Sign) == 0 && !CLI.NoStdin {
		log.Info("Waiting for host descriptions on stdin")

		rdr := bufio.NewScanner(os.Stdin)
		for rdr.Scan() {
			line := rdr.Text()
			hostDescs = append(hostDescs, line)
		}
	} else {
		hostDescs = CLI.Host
	}

	reqDescs := CLI.Request
	signDescs := CLI.Sign

	certificates := []CertData{}
	certRequests := []CertData{}
	signRequests := []CertData{}

	log.Info("Generating certificates...")
	for _, host := range hostDescs {
		log.Info("Generating certificate", zap.String("hostname", host))

		certificates = append(certificates,
			CertData{
				cert: makeCert(time.Now().UnixNano(), CLI.Country, CLI.Organization, CLI.OrganizationalUnit, CLI.Email, caCertCert.cert.NotBefore, caCertCert.cert.NotAfter, host),
				key:  mustPrivateKeyFn(),
			},
		)
	}

	log.Info("Generating certificate signing requests...")
	for _, host := range reqDescs {
		log.Info("Generating certificate signing request", zap.String("hostname", host))

		certRequests = append(certRequests,
			CertData{
				cert: makeCert(time.Now().UnixNano(), CLI.Country, CLI.Organization, CLI.OrganizationalUnit, CLI.Email, caCertCert.cert.NotBefore, caCertCert.cert.NotAfter, host),
				key:  mustPrivateKeyFn(),
			},
		)
	}

	log.Info("Loading certificate signing requests...")
	for _, csrfilename := range signDescs {
		csrLog := log.With(zap.String("filename", csrfilename))
		csrLog.Info("Loading certificate signing requests")

		csrPEMBytes, err := os.ReadFile(csrfilename)
		if err != nil {
			csrLog.Error("Could not read certificate request file")
			return errors.Wrap(err, "Failed to read certificate request from given filename")
		}

		var csrReq *x509.CertificateRequest = nil
		var skippedBlockTypes []string
		for {
			var csrDERBlock *pem.Block
			csrDERBlock, csrPEMBytes = pem.Decode(csrPEMBytes)
			if csrDERBlock == nil {
				break
			}
			if csrDERBlock.Type == "CERTIFICATE REQUEST" {
				if csrReq != nil {
					csrLog.Error("Expected exactly 1 certificate request per file, found more then 1.")
					return ErrMultipleCSRPerFile
				}
				csrReq, err = x509.ParseCertificateRequest(csrDERBlock.Bytes)
				if err != nil {
					csrLog.Error("Error parsing certificate request", zap.Error(err))
					return errors.Wrap(err, "Failed to parse certificate request from file")
				}
			} else {
				skippedBlockTypes = append(skippedBlockTypes, csrDERBlock.Type)
			}
		}

		if len(skippedBlockTypes) > 0 {
			csrLog.Info("Found other block types in CSR file - continuing", zap.Strings("skipped_block_types", skippedBlockTypes))
		}

		if csrReq == nil {
			csrLog.Error("Could not load any certificate requests from file")
			return ErrNoCSRFound
		}

		cert, err := loadCSR(csrReq, time.Now().UnixNano())
		if err != nil {
			return err
		}

		signRequests = append(signRequests,
			CertData{
				cert: cert,
				key:  cert,
			},
		)
	}

	if len(certificates) > 0 || len(signRequests) > 0 || CLI.GenerateCA { //nolint:nestif
		caLog := log.With(zap.String("ca_certificate_filename", caCertificateFilename), zap.String("ca_key_filename", caKeyFilename))
		caLog.Info("CA Certificate filenames")

		shouldGenerate := false

		cert, err := tls.LoadX509KeyPair(caCertificateFilename, caKeyFilename)
		if err == nil {
			caLog.Info("Successfully loaded existing certificates from previous session")
		} else {
			caLog.Info("Could not load existing certificates")
			if CLI.RequireExistingCa {
				caLog.Error("--require-existing-ca but could not load certificate", zap.Error(err))
				return errors.New("--require-existing-ca but could not load certificate")
			}
			shouldGenerate = true
		}

		if CLI.ForceCaGenerate {
			caLog.Info("--force-ca-generate - overwriting any existing files")
			shouldGenerate = true
		}

		if shouldGenerate {
			log.Info("Generating a new CA certificate")

			var notBefore time.Time
			if CLI.StartDate.IsZero() {
				notBefore = time.Now()
				log.Info("No start date specified, using now", zap.Time("start_date", notBefore))
			} else {
				notBefore = CLI.StartDate
				log.Info("Start date specified", zap.Time("start_date", notBefore))
			}

			// time.Duration takes nanoseconds    |--these are nsecs of a day--|
			duration := CLI.Duration
			notAfter := notBefore.Add(duration)
			log.Info("Expiry set", zap.Time("end_date", notAfter), zap.Duration("duration", duration))

			log.Info("Generating CA Certificate",
				zap.String("CommonName", CLI.CommonName),
				zap.String("Country", CLI.Country),
				zap.String("Organization", CLI.Organization),
				zap.String("OrganizationalUnit", CLI.OrganizationalUnit),
				zap.Strings("Email", CLI.Email),
				zap.Time("not_before", notBefore),
				zap.Time("not_after", notAfter),
			)

			caCertCert = CertData{
				cert: func() x509.Certificate {
					caCertCert := makeCert(time.Now().UnixNano(), CLI.Country, CLI.Organization, CLI.OrganizationalUnit, CLI.Email, notBefore, notAfter, CLI.CommonName)
					caCertCert.IsCA = true
					caCertCert.KeyUsage |= x509.KeyUsageCertSign
					return caCertCert
				}(),
				key: mustPrivateKeyFn(),
			}
			// Insert the certificate at the head of the generation queue
			certificates = append([]CertData{caCertCert}, certificates...)
		} else {
			parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				log.Error("Failed to parse certificate from CA certificate file", zap.Error(err))
				return errors.Wrap(err, "Failed to parse CA certificate from file")
			}

			if !parsedCert.IsCA {
				log.Error("Loaded certificate is not a CA certificate. Cannot use for issuing.")
				return ErrNotCertificateAuthority
			}

			caCertCert.cert = *parsedCert
			caCertCert.key = cert.PrivateKey
		}

		if shouldGenerate {
			caLog.Info("Outputting new CA certificate")
			caCertBytes, caKeyBytes, err := caCertCert.EncodeToCerts(caCertCert)
			if err != nil {
				log.Error("Error while encoding CA certificate.")
				return errors.New("error while encoding CA certificate")
			}

			caLog.Info("Outputting CA")
			if err := os.WriteFile(caCertificateFilename, caCertBytes, os.FileMode(CertPermissions)); err != nil {
				caLog.Error("Failed writing file", zap.String("filename", caCertificateFilename), zap.Error(err))
				return errors.New("error writing file")
			}
			if err := os.WriteFile(caKeyFilename, caKeyBytes, os.FileMode(KeyPermissions)); err != nil {
				caLog.Error("Failed writing file", zap.String("filename", caKeyFilename), zap.Error(err))
				return errors.New("error writing file")
			}
		}
	}

	log.Info("Output certificates and keys")
	for _, certData := range certificates {
		log.Info("Signing certificate", zap.String("common_name", certData.cert.Subject.CommonName))
		certBytes, keyBytes, err := certData.EncodeToCerts(caCertCert)
		if err != nil {
			log.Error("Error while encoding certificate", zap.Error(err))
			return errors.Wrap(err, "error wile encoding certificate")
		}

		certFilename := fmt.Sprintf("%s%s%s.%s", CLI.NamePrefix, certData.GetBasename(), CLI.NameSuffix, CLI.CertFileExt)
		keyFilename := fmt.Sprintf("%s%s%s.%s", CLI.NamePrefix, certData.GetBasename(), CLI.NameSuffix, CLI.KeyFileExt)

		log.Info("Outputting certificate", zap.String("certificate_filename", certFilename), zap.String("key_filename", keyFilename))
		if err := os.WriteFile(certFilename, certBytes, os.FileMode(CertPermissions)); err != nil {
			log.Error("Failed writing file:", zap.String("certificate_filename", certFilename), zap.Error(err))
			return errors.Wrap(err, "Failed writing certificate file")
		}
		if err := os.WriteFile(keyFilename, keyBytes, os.FileMode(KeyPermissions)); err != nil {
			log.Error("Failed writing file:", zap.String("key_filename", keyFilename), zap.Error(err))
			return errors.Wrap(err, "Failed writing key file")
		}
	}
	log.Info("Done with certificates")

	log.Info("Output certificate signing requests")
	for _, certData := range certRequests {
		log.Info("Creating certificate request")
		reqBytes, keyBytes, err := certData.EncodeToCertificateSigningRequest()
		if err != nil {
			log.Error("Error while encoding certificate", zap.Error(err))
			return errors.Wrap(err, "error wile encoding certificate")
		}

		certFilename := fmt.Sprintf("%s%s%s.%s", CLI.NamePrefix, certData.GetBasename(), CLI.NameSuffix, CLI.RequestFileExt)
		keyFilename := fmt.Sprintf("%s%s%s.%s", CLI.NamePrefix, certData.GetBasename(), CLI.NameSuffix, CLI.KeyFileExt)

		log.Info("Outputting certificate", zap.String("certificate_request_filename", certFilename), zap.String("key_filename", keyFilename))
		if err := os.WriteFile(certFilename, reqBytes, os.FileMode(CertPermissions)); err != nil {
			log.Error("Failed writing file:", zap.String("certificate_filename", certFilename), zap.Error(err))
			return errors.Wrap(err, "Failed writing certificate file")
		}
		if err := os.WriteFile(keyFilename, keyBytes, os.FileMode(KeyPermissions)); err != nil {
			log.Error("Failed writing file:", zap.String("key_filename", keyFilename), zap.Error(err))
			return errors.Wrap(err, "Failed writing key file")
		}
	}
	log.Info("Done with certificate signing requests")

	log.Info("Signing requests")
	for _, certData := range signRequests {
		log.Info("Signing certificate request", zap.String("common_name", certData.cert.Subject.CommonName))
		certBytes, _, err := certData.EncodeToCerts(caCertCert)
		if err != nil {
			log.Error("Error while encoding certificate", zap.Error(err))
			return errors.Wrap(err, "error wile encoding certificate")
		}

		certFilename := fmt.Sprintf("%s%s%s.%s", CLI.NamePrefix, certData.GetBasename(), CLI.NameSuffix, CLI.CertFileExt)
		keyFilename := fmt.Sprintf("%s%s%s.%s", CLI.NamePrefix, certData.GetBasename(), CLI.NameSuffix, CLI.KeyFileExt)

		log.Info("Outputting certificate", zap.String("certificate_filename", certFilename), zap.String("key_filename", keyFilename))
		if err := os.WriteFile(certFilename, certBytes, os.FileMode(CertPermissions)); err != nil {
			log.Error("Failed writing file:", zap.String("certificate_filename", certFilename), zap.Error(err))
			return errors.Wrap(err, "Failed writing certificate file")
		}
	}
	log.Info("Done signing requests")

	log.Info("Certificate generation finished")
	return nil
}
