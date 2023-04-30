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
	"io/ioutil"
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

// Version is set during build to the current git commitish.
var Version = "development"

// PrivateKeyGenerator wraps the function signature for RSA and Elliptic key generators.
type PrivateKeyGenerator func() (interface{}, error)

// commonNameToFilename converts a common name to a standard-ish output format.
func commonNameToFilename(cn string) string {
	outstr := strings.Replace(cn, ".", "_", -1)
	outstr = strings.Replace(outstr, "*", "STAR", -1)
	return outstr
}

// CertData holds the tuple of certificate data.
type CertData struct {
	cert x509.Certificate
	key  interface{}
}

// EncodeToCerts signs the certificate and with the given CA ceertificate and returns the PEM encoded certs.
func (cd *CertData) EncodeToCerts(signing CertData) ([]byte, []byte, error) {
	derCABytes, err := x509.CreateCertificate(rand.Reader, &cd.cert, &signing.cert, publicKey(cd.key), signing.key)
	if err != nil {
		return nil, nil, err
	}
	caCertBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCABytes})
	caKeyBytes := pem.EncodeToMemory(pemBlockForKey(cd.key))
	return caCertBytes, caKeyBytes, nil
}

// GetBasename returns the filename of the certificate.
func (cd *CertData) GetBasename() string {
	return commonNameToFilename(cd.cert.Subject.CommonName)
}

// publicKey detects the type of key and returns its PublicKey.
func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
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
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
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

	CertFileExt string `help:"Certificate file extension to add to public keys" default:"crt"`
	KeyFileExt  string `help:"Certificate file extension to add to private keys" default:"pem"`

	UseCACert string `help:"Load a CA certificate from a file rather then generating a new one"`
	UseCAKey  string `help:"Load a CA private key from a file rather then generating a new one"`

	HostSpec []string `help:"Hostname to generate a certificate for"`
}

func realMain() error {
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
	_, cancelFn := context.WithCancel(context.Background())
	go func() {
		sig := <-sigCh
		log.Info("Caught signal - exiting", zap.String("signal", sig.String()))
		cancelFn()
	}()

	// Setup a new key generation interface
	var privateKeyFn PrivateKeyGenerator

	switch CLI.EcdsaCurve {
	case "":
		privateKeyFn = func() (interface{}, error) {
			return rsa.GenerateKey(rand.Reader, CLI.RsaBits)
		}
		// P224 curve is disabled because Red Hat disable it.
	case "P256":
		privateKeyFn = func() (interface{}, error) {
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
	case "P384":
		privateKeyFn = func() (interface{}, error) {
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		}
	case "P521":
		privateKeyFn = func() (interface{}, error) {
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
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

	if CLI.UseCACert != "" || CLI.UseCAKey != "" {
		log.Info("Loading CA certificate from file:", zap.String("public_key", CLI.UseCACert), zap.String("private_key", CLI.UseCAKey))

		cert, err := tls.LoadX509KeyPair(CLI.UseCACert, CLI.UseCAKey)
		if err != nil {
			log.Fatal("Error loading X509 CA keypair", zap.Error(err))
		}

		caCertCert.cert = *cert.Leaf
		caCertCert.key = cert.PrivateKey

	} else {
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
	}

	hostDescs := []string{}

	if len(CLI.HostSpec) == 0 {
		log.Info("Waiting for host descriptions on stdin")

		rdr := bufio.NewScanner(os.Stdin)
		for rdr.Scan() {
			line := rdr.Text()
			hostDescs = append(hostDescs, line)
		}
	} else {
		hostDescs = CLI.HostSpec
	}

	log.Info("Generating certificates.")
	certificates := []CertData{caCertCert}
	for _, host := range hostDescs {
		log.Info("Generating certificate", zap.String("hostname", host))

		certificates = append(certificates,
			CertData{
				cert: makeCert(time.Now().UnixNano(), CLI.Country, CLI.Organization, CLI.OrganizationalUnit, CLI.Email, caCertCert.cert.NotBefore, caCertCert.cert.NotAfter, host),
				key:  mustPrivateKeyFn(),
			},
		)
	}

	// Sign certificate
	{
		log.Info("Signing CA certificate")
		caCertBytes, caKeyBytes, err := caCertCert.EncodeToCerts(caCertCert)
		if err != nil {
			log.Error("Error while encoding CA certificate.")
			return errors.New("error while encoding CA certificate")
		}

		caCertFilename := fmt.Sprintf("%s%s%s.%s", CLI.NamePrefix, caCertCert.GetBasename(), CLI.NameSuffix, CLI.CertFileExt)
		caKeyFilename := fmt.Sprintf("%s%s%s.%s", CLI.NamePrefix, caCertCert.GetBasename(), CLI.NameSuffix, CLI.KeyFileExt)

		log.Info("Outputting CA", zap.String("certificate_filename", caCertFilename), zap.String("key_filename", caKeyFilename))
		if err := ioutil.WriteFile(caCertFilename, caCertBytes, os.FileMode(0644)); err != nil {
			log.Error("Failed writing file", zap.String("filename", caCertFilename), zap.Error(err))
			return errors.New("error writing file")
		}
		if err := ioutil.WriteFile(caKeyFilename, caKeyBytes, os.FileMode(0600)); err != nil {
			log.Error("Failed writing file", zap.String("filename", caKeyFilename), zap.Error(err))
			return errors.New("error writing file")
		}
	}

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
		if err := ioutil.WriteFile(certFilename, certBytes, os.FileMode(0644)); err != nil {
			log.Error("Failed writing file:", zap.String("certificate_filename", certFilename), zap.Error(err))
			return err
		}
		if err := ioutil.WriteFile(keyFilename, keyBytes, os.FileMode(0600)); err != nil {
			log.Error("Failed writing file:", zap.String("key_filename", keyFilename), zap.Error(err))
			return err
		}
	}

	log.Info("Files written succesfully. Exiting.")
	return nil
}
