package certspec_test

import (
	"crypto/x509"
	"testing"

	"github.com/wrouesnel/makecerts/pkg/certspec"

	"github.com/spf13/afero"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type SpecSuite struct {
	fs afero.Fs
}

var _ = Suite(&SpecSuite{})

func (s *SpecSuite) TestCertSpecificationUnmarshal(c *C) {
	var err error

	cs := &certspec.CertSpecification{}

	err = cs.UnmarshalText([]byte("localhost"))
	c.Assert(err, IsNil)

	err = cs.UnmarshalText([]byte("localhost?usage=digitalsignature&extusage=serverauth,clientauth&extusage=codesigning&ca=true"))
	c.Assert(err, IsNil)
	c.Assert(cs.Hosts, DeepEquals, []string{"localhost"})
	c.Assert(cs.KeyUsage, Equals, x509.KeyUsageDigitalSignature)
	c.Assert(cs.ExtKeyUsage, DeepEquals, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning})
	c.Assert(cs.IsCa, Equals, true)
}
