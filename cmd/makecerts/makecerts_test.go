package main

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
		"--host", hostname,
	}

	err = realMain()
	c.Assert(err, IsNil)

	// Expect certificate names
	dentries, err := os.ReadDir(dir)
	c.Assert(err, IsNil)

	expectedFileNames := []string{"localhost.ca.crt", "localhost.ca.pem", "example0.crt", "example0.pem"}
	generatedFileNames := lo.Map(dentries, func(item os.DirEntry, index int) string {
		return item.Name()
	})

	c.Assert(len(lo.Without(generatedFileNames, expectedFileNames...)), Equals, 0, Commentf("Got extra files after generation"))

	// Check the certificates are parseable
	caCerts, err := tls.LoadX509KeyPair("localhost.ca.crt", "localhost.ca.pem")
	c.Assert(err, IsNil, Commentf("Failed to load the generated CA certificates"))

	caCertParsed, err := x509.ParseCertificate(caCerts.Certificate[0])
	c.Assert(err, IsNil, Commentf("Failed to load the generated CA certificates"))
	c.Assert(caCertParsed.IsCA, Equals, true)
	c.Assert(time.Now().After(caCertParsed.NotBefore), Equals, true, Commentf("NotBefore wasn't valid right now: %s", caCertParsed.NotBefore.String()))
	c.Assert(time.Now().Before(caCertParsed.NotAfter), Equals, true, Commentf("NotAfter wasn't valid right now: %s", caCertParsed.NotAfter.String()))

	generatedCert, err := tls.LoadX509KeyPair("example0.crt", "example0.pem")
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

	os.Args = []string{"makecerts",
		"--common-name=rootCA",
		"--host", "example0.com",
		"--host", "example1.com",
		"--host", "example2.com",
		"--host", "example3.com",
	}

	err = realMain()
	c.Assert(err, IsNil)
}

func (s *FunctionalSuite) TestECCertifcateGeneration(c *C) {
	// Run a basic check
	dir, err := os.MkdirTemp("", "")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	err = os.Chdir(dir)
	c.Assert(err, IsNil)

	for _, curve := range []string{"P256", "P384", "P521"} {
		os.Args = []string{"makecerts",
			fmt.Sprintf("--ecdsa-curve=%s", curve),
			"--common-name=ecdsaCA",
			"--host", "ec-example0.com",
			"--host", "ec-example1.com",
			"--host", "ec-example2.com",
			"--host", "ec-example3.com",
		}
		err := realMain()
		c.Assert(err, IsNil)
	}
}
