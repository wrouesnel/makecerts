package main

import (
	"testing"

	. "gopkg.in/check.v1"

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
