//

package main

import (
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
	"strings"
	"time"

	"bufio"
	"crypto/tls"
	"gopkg.in/alecthomas/kingpin.v2"
	"sync"
)

// Version is set during build to the current git commitish
var Version = "development"

// PrivateKeyGenerator wraps the function signature for RSA and Elliptic key generators
type PrivateKeyGenerator func() (interface{}, error)

// commonNameToFilename converts a common name to a standard-ish output format.
func commonNameToFilename(cn string) string {
	outstr := strings.Replace(cn, ".", "_", -1)
	outstr = strings.Replace(outstr, "*", "STAR", -1)
	return outstr
}

// CertData holds the tuple of certificate data
type CertData struct {
	cert       x509.Certificate
	key        interface{}
	outputName string
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
	if cd.outputName != "" {
		return cd.outputName
	}
	return commonNameToFilename(cd.cert.Subject.CommonName)
}

// publicKey detects the type of key and returns its PublicKey
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
// according to its type
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
func makeCert(serialNumber int64, cAttr string, oAttr string, ouAttr string, email string, notBefore time.Time, notAfter time.Time, hosts string) x509.Certificate {
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
	if len(email) > 0 {
		emails := strings.Split(email, ",")
		template.EmailAddresses = append(template.EmailAddresses, emails...)
	}

	return template
}

func realMain() error {
	app := kingpin.New("makecerts", "Quickly generate a CA and certificates for a list of hosts.")
	app.Version(Version)

	hosts := app.Arg("hosts", "List of comma-separated strings marking hostnames and IPs to generate certificates for. If blank, reads from stdin. Use = to specify output filename as <filename>=<hosts>").Strings()

	caHost := app.Flag("CN", "CA Certificate Common Name, as in 'example.com'").String()
	cAttr := app.Flag("C", "Certificate attribute: Country").Default("Test Country").String()
	oAttr := app.Flag("O", "Certificate attribute: Organization").Default("Test Org").String()
	ouAttr := app.Flag("OU", "Certificate attribute: Organizational Unit").Default("Test OU").String()
	email := app.Flag("emails", "Comma-separated emails to be added to the certificates").Default("test@test").String()

	validFrom := app.Flag("start-date", "Creation date formatted as Jan 1 15:04:05 2011").Default(time.Now().Format(time.UnixDate)).String()
	validFor := app.Flag("duration", "Duration in days that certificate is valid for").Default("365.25").Float64()

	rsaBits := app.Flag("rsa-bits", "Size of RSA key to generate. Ignored if --ecdsa-curve is set").Default("4096").Int()
	ecdsaCurve := app.Flag("ecdsa-curve", "ECDSA curve to use to generate a key. Valid values are P256, P384, P521").Default("").Enum("P256", "P384", "P521", "")

	namePrefix := app.Flag("name-prefix", "Filename prefix to add to certificates").String()
	nameSuffix := app.Flag("name-suffix", "Filename suffix to add to certificates before extension").String()

	certFileExt := app.Flag("cert-file-ext", "Certificate file extension to add to public keys").Default("crt").String()
	keyFileExt := app.Flag("key-file-ext", "Certificate file extension to add to private keys").Default("pem").String()

	caCertFile := app.Flag("load-ca-cert", "Load a CA certificate from a file rather then generating a new one (must specify load-ca-key").String()
	caKeyFile := app.Flag("load-ca-key", "Load a CA private key from a file rather then generating a new one (must specify load-ca-cert)").String()

	kingpin.MustParse(app.Parse(os.Args[1:]))

	if *caCertFile != "" || *caKeyFile != "" {
		if *caCertFile == "" || *caKeyFile == "" {
			log.Panicln("Must specify both CA cert file and CA key file to use existing certificate authority.")
		}
	}

	// Setup a new key generation interface
	var privateKeyFn PrivateKeyGenerator

	switch *ecdsaCurve {
	case "":
		privateKeyFn = func() (interface{}, error) {
			return rsa.GenerateKey(rand.Reader, *rsaBits)
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
		log.Panicln("Unrecognized elliptic curve:", *ecdsaCurve)
	}

	mustPrivateKeyFn := func() interface{} {
		caCertKey, err := privateKeyFn()
		if err != nil {
			log.Panicln("Could not generate private key:", err)
		}
		return caCertKey
	}

	var caCertCert CertData

	if *caCertFile != "" && *caKeyFile != "" {
		log.Println("Loading CA certificate from file:", *caCertFile)
		log.Println("Loading CA key from file:", *caKeyFile)

		cert, err := tls.LoadX509KeyPair(*caCertFile, *caKeyFile)
		if err != nil {
			log.Panicln("Error loading X509 CA keypair:", err)
		}

		caCerts := []*x509.Certificate{}
		for _, certData := range cert.Certificate {
			parsedCertificate, err := x509.ParseCertificate(certData)
			if err != nil {
				log.Panicln("Could not parse certificate of loaded CA:", err)
			}
			caCerts = append(caCerts, parsedCertificate)
		}

		cert.Leaf = caCerts[0]

		caCertCert.cert = *cert.Leaf
		caCertCert.key = cert.PrivateKey

	} else {
		var err error

		var notBefore time.Time
		if len(*validFrom) == 0 {
			notBefore = time.Now()
		} else {
			notBefore, err = time.Parse(time.UnixDate, *validFrom)
			if err != nil {
				log.Panicln("Failed to parse creation date: ", err)
			}
		}

		// time.Duration takes nanoseconds    |--these are nsecs of a day--|
		duration := time.Duration(*validFor * 24 * 3600 * 1000 * 1000 * 1000)
		notAfter := notBefore.Add(duration)

		log.Println("Generating CA certificate.")

		caCertCert = CertData{
			cert: func() x509.Certificate {
				caCertCert := makeCert(time.Now().UnixNano(), *cAttr, *oAttr, *ouAttr, *email, notBefore, notAfter, *caHost)
				caCertCert.IsCA = true
				caCertCert.KeyUsage |= x509.KeyUsageCertSign
				return caCertCert
			}(),
			key: mustPrivateKeyFn(),
		}
	}

	hostDescs := []string{}

	if len(*hosts) == 0 {
		log.Println("Waiting for host descriptions on stdin")

		rdr := bufio.NewScanner(os.Stdin)
		for rdr.Scan() {
			line := rdr.Text()
			hostDescs = append(hostDescs, line)
		}
	} else {
		hostDescs = *hosts
	}

	log.Println("Generating certificates.")
	certificates := make([]CertData, len(hostDescs)+1)
	certificates[0] = caCertCert
	certificateWaitGroup := &sync.WaitGroup{}
	for idx, hostDesc := range hostDescs {
		certificateWaitGroup.Add(1)
		go func(cidx int, hostDesc string) {
			defer certificateWaitGroup.Done()

			outputName := ""
			hostnames := hostDesc
			outNamesTuple := strings.SplitN(hostDesc, "=", 2)
			if len(outNamesTuple) > 1 {
				outputName = outNamesTuple[0]
				hostnames = outNamesTuple[1]
			}

			log.Println("Generating certificate for", hostnames)

			certData := CertData{
				cert:       makeCert(time.Now().UnixNano(), *cAttr, *oAttr, *ouAttr, *email, caCertCert.cert.NotBefore, caCertCert.cert.NotAfter, hostnames),
				key:        mustPrivateKeyFn(),
				outputName: outputName,
			}
			certificates[cidx] = certData
			log.Println("Finished generating certificate for", hostDesc)
		}(idx+1, hostDesc)
	}
	// Wait for certificates to be generated...
	certificateWaitGroup.Wait()

	// Sign certificate
	{
		log.Println("Signing CA certificate")
		caCertBytes, caKeyBytes, err := caCertCert.EncodeToCerts(caCertCert)
		if err != nil {
			log.Panicln("Error while encoding CA certificate.")
		}

		nameFmtString := "%s"
		if *namePrefix != "" {
			nameFmtString = *namePrefix + "." + nameFmtString
		}

		if *nameSuffix != "" {
			nameFmtString = nameFmtString + "." + *nameSuffix
		}

		certFileFmtString := nameFmtString
		keyFileFmtString := nameFmtString
		if *certFileExt != "" {
			certFileFmtString = certFileFmtString + "." + *certFileExt
		}

		if *keyFileExt != "" {
			keyFileFmtString = keyFileFmtString + "." + *keyFileExt
		}

		caCertFilename := fmt.Sprintf(certFileFmtString, caCertCert.GetBasename())
		caKeyFilename := fmt.Sprintf(keyFileFmtString, caCertCert.GetBasename())

		log.Printf("Outputting CA: cert=%s key=%s", caCertFilename, caKeyFilename)
		if err := ioutil.WriteFile(caCertFilename, caCertBytes, os.FileMode(0644)); err != nil {
			log.Panicln("Failed writing file:", caCertFilename, err)
		}
		if err := ioutil.WriteFile(caKeyFilename, caKeyBytes, os.FileMode(0600)); err != nil {
			log.Panicln("Failed writing file:", caCertFilename, err)
		}
	}

	for _, certData := range certificates {
		log.Println("Signing certificate:", certData.cert.Subject.CommonName)
		certBytes, keyBytes, err := certData.EncodeToCerts(caCertCert)
		if err != nil {
			log.Panicln("Error while encoding certificate")
		}

		nameFmtString := "%s"
		if *namePrefix != "" {
			nameFmtString = *namePrefix + "." + nameFmtString
		}

		if *nameSuffix != "" {
			nameFmtString = nameFmtString + "." + *nameSuffix
		}

		certFileFmtString := nameFmtString
		keyFileFmtString := nameFmtString
		if *certFileExt != "" {
			certFileFmtString = certFileFmtString + "." + *certFileExt
		}

		if *keyFileExt != "" {
			keyFileFmtString = keyFileFmtString + "." + *keyFileExt
		}

		certFilename := fmt.Sprintf(certFileFmtString, certData.GetBasename())
		keyFilename := fmt.Sprintf(keyFileFmtString, certData.GetBasename())

		log.Printf("Outputting: cert=%s key=%s", certFilename, keyFilename)
		if err := ioutil.WriteFile(certFilename, certBytes, os.FileMode(0644)); err != nil {
			log.Panicln("Failed writing file:", certFilename, err)
		}
		if err := ioutil.WriteFile(keyFilename, keyBytes, os.FileMode(0600)); err != nil {
			log.Panicln("Failed writing file:", keyFilename, err)
		}
	}

	log.Println("Files written succesfully. Exiting.")
	return nil
}
