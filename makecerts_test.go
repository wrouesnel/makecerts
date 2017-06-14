package main

import (
	. "gopkg.in/check.v1"
	"testing"

	"fmt"
	"io/ioutil"
	"os"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type FunctionalSuite struct{}

var _ = Suite(&FunctionalSuite{})

func (s *FunctionalSuite) TestCertificateGeneration(c *C) {
	// Run a basic check
	dir, err := ioutil.TempDir("", "")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir) // nolint: errcheck

	err = os.Chdir(dir)
	c.Assert(err, IsNil)

	os.Args = []string{"makecerts",
		"--CN=rootCA",
		"example0.com",
		"example1.com",
		"example2.com",
		"example3.com",
	}

	err = realMain()
	c.Assert(err, IsNil)

	// Test generating additional certificates using the CA
	os.Args = []string{"makecerts",
		"--load-ca-cert=rootCA.crt",
		"--load-ca-key=rootCA.pem",
		"example5.com",
		"example6.com",
	}

	err = realMain()
	c.Assert(err, IsNil)

	// Test the elliptic curve generation
	for _, curve := range []string{"P256", "P384", "P521"} {
		os.Args = []string{"makecerts",
			fmt.Sprintf("--ecdsa-curve=%s", curve),
			"--CN=ecdsaCA",
			"ec-example0.com",
			"ec-example1.com",
			"ec-example2.com",
			"ec-example3.com",
		}
		err := realMain()
		c.Assert(err, IsNil)
	}
}
