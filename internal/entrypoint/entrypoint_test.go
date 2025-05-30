package entrypoint

import (
	"crypto/tls"
	"crypto/x509"

	"testing"
	"time"

	"github.com/samber/lo"

	. "gopkg.in/check.v1"

	"fmt"
	"os"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type FunctionalSuite struct{}

var _ = Suite(&FunctionalSuite{})

func (s *FunctionalSuite) TestCertificateGeneration(c *C) {
	// Run a basic check
	dir, err := os.MkdirTemp("", "")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	err = os.Chdir(dir)
	c.Assert(err, IsNil)

	const hostname = "example0"

	os.Args = []string{"makecerts",
		"certificate", hostname,
	}

	err = Entrypoint(os.Stdout, os.Stderr, os.Stdin)
	c.Assert(err, IsNil)

	// Expect certificate names
	dentries, err := os.ReadDir(dir)
	c.Assert(err, IsNil)

	expectedFileNames := []string{"localhost.ca.crt", "localhost.ca.key", "example0.crt", "example0.key"}
	generatedFileNames := lo.Map(dentries, func(item os.DirEntry, index int) string {
		return item.Name()
	})

	c.Assert(len(lo.Without(generatedFileNames, expectedFileNames...)), Equals, 0, Commentf("Got extra files after generation"))

	// Check the certificates are parseable
	caCerts, err := tls.LoadX509KeyPair("localhost.ca.crt", "localhost.ca.key")
	c.Assert(err, IsNil, Commentf("Failed to load the generated CA certificates"))

	caCertParsed, err := x509.ParseCertificate(caCerts.Certificate[0])
	c.Assert(err, IsNil, Commentf("Failed to load the generated CA certificates"))
	c.Assert(caCertParsed.IsCA, Equals, true)
	c.Assert(time.Now().After(caCertParsed.NotBefore), Equals, true, Commentf("NotBefore wasn't valid right now: %s", caCertParsed.NotBefore.String()))
	c.Assert(time.Now().Before(caCertParsed.NotAfter), Equals, true, Commentf("NotAfter wasn't valid right now: %s", caCertParsed.NotAfter.String()))

	generatedCert, err := tls.LoadX509KeyPair("example0.crt", "example0.key")
	c.Assert(err, IsNil, Commentf("Failed to load the generated signed certificates"))

	generatedCertParsed, err := x509.ParseCertificate(generatedCert.Certificate[0])
	c.Assert(err, IsNil, Commentf("Failed to load the generated CA certificates"))
	c.Assert(generatedCertParsed.Subject.CommonName, Equals, hostname)
	c.Assert(time.Now().After(generatedCertParsed.NotBefore), Equals, true, Commentf("NotBefore wasn't valid right now: %s", generatedCertParsed.NotBefore.String()))
	c.Assert(time.Now().Before(generatedCertParsed.NotAfter), Equals, true, Commentf("NotAfter wasn't valid right now: %s", generatedCertParsed.NotBefore.String()))
}

func (s *FunctionalSuite) TestRSACertificateGeneration(c *C) {
	// Run a basic check
	dir, err := os.MkdirTemp("", "")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	err = os.Chdir(dir)
	c.Assert(err, IsNil)

	os.Args = []string{"makecerts", "--private-key-type=rsa2048",
		"--ca-common-name=rootCA",
		"certificate",
		"example0.com",
		"example1.com",
		"example2.com",
		"example3.com",
	}

	err = Entrypoint(os.Stdout, os.Stderr, os.Stdin)
	c.Assert(err, IsNil)
}

func (s *FunctionalSuite) TestECCertifcateGeneration(c *C) {
	// Run a basic check
	dir, err := os.MkdirTemp("", "")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	err = os.Chdir(dir)
	c.Assert(err, IsNil)

	for _, curve := range []string{"ecp256", "ecp384", "ecp521"} {
		os.Args = []string{"makecerts",
			fmt.Sprintf("--private-key-type=%s", curve),
			"--ca-common-name=ecdsaCA",
			"certificate",
			"ec-example0.com",
			"ec-example1.com",
			"ec-example2.com",
			"ec-example3.com",
		}
		err = Entrypoint(os.Stdout, os.Stderr, os.Stdin)
		c.Assert(err, IsNil)
	}
}
