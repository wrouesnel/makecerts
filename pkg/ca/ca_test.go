package ca_test

import (
	"github.com/spf13/afero"
	"github.com/wrouesnel/certutils"
	"github.com/wrouesnel/makecerts/pkg/ca"
	"github.com/wrouesnel/makecerts/pkg/models"
	"go.uber.org/zap"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type CaSuite struct {
	fs afero.Fs
}

var _ = Suite(&CaSuite{})

func (s *CaSuite) SetUpSuite(c *C) {
	l, err := zap.NewDevelopment()
	c.Assert(err, IsNil)
	zap.ReplaceGlobals(l)

	tmpDir := c.MkDir()
	s.fs = afero.NewBasePathFs(afero.NewOsFs(), tmpDir)
}

func (s *CaSuite) TearDownSuite(c *C) {
	zap.L().Sync()
}

// TestHandleCACertificate
func (s *CaSuite) TestHandleCACertificate(c *C) {
	fsConfig := models.CertificateFilenameConfig{
		CACertName:     "",
		CAKeyName:      "",
		CACSRName:      "",
		CaPrefix:       "",
		CaSuffix:       "ca",
		NamePrefix:     "",
		NameSuffix:     "",
		CertFileExt:    "crt",
		KeyFileExt:     "key",
		RequestFileExt: "csr",
	}

	caConfig := ca.CaConfig{
		CommonName:         c.TestName(),
		Country:            "INT",
		Organization:       "ca_test",
		OrganizationalUnit: "Root CA",
		Duration:           time.Hour,
	}

	keyType := certutils.PrivateKeyTypeEcp256

	// Expect failure
	existingCertPair, err := ca.HandleCACertificate(s.fs, fsConfig, caConfig, ca.CaModeExisting, keyType)
	c.Assert(err, Not(IsNil), Commentf("should've failed to find a CA since we haven't made one"))
	c.Assert(existingCertPair, IsNil, Commentf("should've failed to find a CA since we haven't made one"))

	// Generate a new CA
	certPair, err := ca.HandleCACertificate(s.fs, fsConfig, caConfig, ca.CaModeGenerate, keyType)
	c.Assert(err, IsNil)
	c.Assert(certPair, Not(IsNil))

	// Try generating again - we should get back the same CA
	newCertPair, err := ca.HandleCACertificate(s.fs, fsConfig, caConfig, ca.CaModeGenerate, keyType)
	c.Assert(err, IsNil)
	c.Assert(newCertPair, Not(IsNil))

	c.Assert(newCertPair.Cert.Raw, DeepEquals, certPair.Cert.Raw, Commentf("did not get the same certificate back"))

	// Expect success
	existingCertPair, err = ca.HandleCACertificate(s.fs, fsConfig, caConfig, ca.CaModeExisting, keyType)
	c.Assert(err, IsNil, Commentf("should've found a CA"))
	c.Assert(existingCertPair, Not(IsNil), Commentf("should've found a CA"))
	c.Assert(existingCertPair.Cert.Raw, DeepEquals, certPair.Cert.Raw, Commentf("did not get the same certificate back"))
}
