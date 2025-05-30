//go:generate go tool go-enum --lower
package entrypoint

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/chigopher/pathlib"
	"github.com/samber/lo"
	"github.com/spf13/afero"
	"github.com/wrouesnel/certutils"
	"github.com/wrouesnel/ctxstdio"
	"github.com/wrouesnel/makecerts/pkg/ca"
	"github.com/wrouesnel/makecerts/pkg/certspec"
	"github.com/wrouesnel/makecerts/pkg/models"
	"github.com/wrouesnel/makecerts/pkg/util"
	"github.com/yuseferi/zax/v2"
	"go.uber.org/zap"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

var ErrCommandErr = errors.New("Invalid certificate specifications")
var ErrCertErr = errors.New("error generating certificate")

// CertOperations is the list of possible operation categories
// ENUM(certificate,sign,request)
type CertOperations string

// MakeCerts implements the makcerts command
func MakeCerts(ctx context.Context) error {
	l := zap.L().With(zax.Get(ctx)...)
	fs := afero.NewOsFs()

	var err error

	l.Debug("Validating Commands")
	var commandErr error
	var currentOp CertOperations
	ops := map[CertOperations][]certspec.CertSpecification{}

	if len(CLI.Commands) == 0 && !CLI.NoStdin {
		l.Debug("Reading from stdin")
		bio := bufio.NewScanner(ctxstdio.Stdin(ctx))
		for bio.Scan() {
			line := bio.Text()
			if !currentOp.IsValid() {
				currentOp, err = ParseCertOperations(line)
				if err != nil {
					l.Error("Invalid certificate operation", zap.String("operation", line))
					return err
				}
				continue
			}
		}
		select {
		case <-ctx.Done():
			l.Warn("context finished: aborting")
			return ctx.Err()
		default:
		}
	} else if len(CLI.Commands) > 0 {
		l.Debug("Reading from command line")
	}

	for _, command := range CLI.Commands {
		if !currentOp.IsValid() {
			currentOp, err = ParseCertOperations(command)
			if err != nil {
				l.Error("Invalid certificate operation", zap.String("operation", command))
				return err
			}
			continue
		}

		spec := certspec.CertSpecification{}
		if err := spec.UnmarshalText([]byte(command)); err != nil {
			l.Error("Invalid specificaton", zap.String("line", command), zap.String("error", err.Error()))
			commandErr = ErrCommandErr
		}
		ops[currentOp] = append(ops[currentOp], spec)
	}

	if commandErr != nil {
		return commandErr
	}

	l.Info("Parsed Specifications", zap.Int("certificates", len(ops[CertOperationsCertificate])),
		zap.Int("signatures", len(ops[CertOperationsSign])), zap.Int("csrs", len(ops[CertOperationsRequest])))

	var caCert *models.X509CertificateAndKey
	if len(ops[CertOperationsCertificate]) > 0 || len(ops[CertOperationsSign]) > 0 {
		l.Debug("Handling CA certificate")
		caCert, err = ca.HandleCACertificate(fs, CLI.FilenameConfig, CLI.Ca, CLI.CaMode, CLI.PrivateKeyType)
		if err != nil {
			return err
		}
	}

	commonUsages := x509.KeyUsage(0)
	commonExtUsages := []x509.ExtKeyUsage{}

	if len(CLI.Usage) > 0 || len(CLI.ExtendedUsage) > 0 {
		l.Info("Applying user supplied certificate extensions")
		for _, usage := range CLI.Usage {
			commonUsages |= usage.KeyUsage
		}
		for _, extUsage := range CLI.ExtendedUsage {
			commonExtUsages = append(commonExtUsages, extUsage.ExtKeyUsage)
		}
		commonExtUsages = lo.Uniq(commonExtUsages)
	} else {
		// Default certificate common usage to a basic TLS server.
		l.Info("Applying default certificate extensions")
		commonUsages = x509.KeyUsageDigitalSignature
		commonExtUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	if len(ops[CertOperationsRequest]) > 0 {
		if err := generateRequests(ctx, fs, commonUsages, commonExtUsages, ops[CertOperationsRequest]); err != nil {
			return err
		}
	}

	if len(ops[CertOperationsCertificate]) > 0 {
		if err := generateCertificates(ctx, fs, caCert, commonUsages, commonExtUsages, ops[CertOperationsCertificate]); err != nil {
			return err
		}
	}

	if len(ops[CertOperationsSign]) > 0 {
		if err := generateSignatures(ctx, fs, caCert, ops[CertOperationsSign]); err != nil {
			return err
		}
	}

	return nil
}

func generateRequests(ctx context.Context, fs afero.Fs, commonUsage x509.KeyUsage, commonExtUsage []x509.ExtKeyUsage, specs []certspec.CertSpecification) error {
	l := zap.L().With(zax.Get(ctx)...)
	l.Info("Generating requested CSRs")
	for _, spec := range specs {
		l.Debug("Generating new CSR for subjects", zap.Strings("subjects", spec.Hosts))
		csr, key, err := csrFromSpec(ctx, CLI.Ca, commonUsage, commonExtUsage, CLI.PrivateKeyType, spec)
		if err != nil {
			return err
		}

		if spec.CSRFile == "" {
			spec.CSRFile = fmt.Sprintf("%s.%s", certificateNameBuilder(CLI.FilenameConfig, spec.Hosts[0]), CLI.FilenameConfig.RequestFileExt)
		}

		if spec.KeyFile == "" {
			spec.KeyFile = fmt.Sprintf("%s.%s", certificateNameBuilder(CLI.FilenameConfig, spec.Hosts[0]), CLI.FilenameConfig.KeyFileExt)
		}

		csrPath := pathlib.NewPath(spec.CSRFile, pathlib.PathWithAfero(fs))
		keyPath := pathlib.NewPath(spec.KeyFile, pathlib.PathWithAfero(fs))

		csrPEMbytes, err := certutils.EncodeRequest(csr)
		if err != nil {
			return err
		}

		keyPEMbytes, err := certutils.EncodeKeys(key)
		if err != nil {
			return err
		}

		if err := csrPath.WriteFile(csrPEMbytes); err != nil {
			return err
		}

		if err := keyPath.WriteFileMode(keyPEMbytes, os.FileMode(0600)); err != nil {
			return err
		}
		l.Info("Wrote certificate request", zap.String("csr_path", csrPath.String()), zap.String("key_path", keyPath.String()))
	}
	return nil
}

func generateCertificates(ctx context.Context, fs afero.Fs, caCert *models.X509CertificateAndKey, commonUsage x509.KeyUsage, commonExtUsage []x509.ExtKeyUsage, specs []certspec.CertSpecification) error {
	l := zap.L().With(zax.Get(ctx)...)
	l.Info("Generating requested certificates")
	for _, spec := range specs {
		l.Debug("Generating new CSR for subjects", zap.Strings("subjects", spec.Hosts))
		csr, key, err := csrFromSpec(ctx, CLI.Ca, commonUsage, commonExtUsage, CLI.PrivateKeyType, spec)
		if err != nil {
			return err
		}

		signingParams := certutils.SigningParameters{
			SerialNumber: time.Now().UnixNano(),
			NotBefore:    certutils.CertificateNotBefore(),
			NotAfter:     time.Now().Add(CLI.Duration),
		}

		l.Debug("Signing CSR for subjects", zap.Strings("subjects", spec.Hosts))
		cert, err := certutils.SignCertificate(csr, caCert.Cert, caCert.Key, signingParams)
		if err != nil {
			return err
		}

		if spec.CertificateFile == "" {
			spec.CertificateFile = fmt.Sprintf("%s.%s", certificateNameBuilder(CLI.FilenameConfig, spec.Hosts[0]), CLI.FilenameConfig.CertFileExt)

		}

		if spec.KeyFile == "" {
			spec.KeyFile = fmt.Sprintf("%s.%s", certificateNameBuilder(CLI.FilenameConfig, spec.Hosts[0]), CLI.FilenameConfig.KeyFileExt)
		}

		certPath := pathlib.NewPath(spec.CertificateFile, pathlib.PathWithAfero(fs))
		keyPath := pathlib.NewPath(spec.KeyFile, pathlib.PathWithAfero(fs))

		certPEMbytes, err := certutils.EncodeCertificates(cert)
		if err != nil {
			return err
		}

		keyPEMbytes, err := certutils.EncodeKeys(key)
		if err != nil {
			return err
		}

		if err := certPath.WriteFile(certPEMbytes); err != nil {
			return err
		}

		if err := keyPath.WriteFileMode(keyPEMbytes, os.FileMode(0600)); err != nil {
			return err
		}
		l.Info("Wrote certificates", zap.String("cert_path", certPath.String()), zap.String("key_path", keyPath.String()))
	}
	return nil
}

// generateSignatures signs the provided certificate specifications
func generateSignatures(ctx context.Context, fs afero.Fs, caCert *models.X509CertificateAndKey, specs []certspec.CertSpecification) error {
	l := zap.L().With(zax.Get(ctx)...)
	l.Info("Generating signed certificates")
	for _, spec := range specs {
		if spec.CSRFile == "" {
			spec.CSRFile = fmt.Sprintf("%s.%s", certificateNameBuilder(CLI.FilenameConfig, spec.Hosts[0]), CLI.FilenameConfig.RequestFileExt)
		}
		l.Debug("Loading CSR file", zap.String("csr_file", spec.CSRFile))

		csrPath := pathlib.NewPath(spec.CSRFile, pathlib.PathWithAfero(fs))
		csrBytes, err := csrPath.ReadFile()
		if err != nil {
			return err
		}

		csrs, err := certutils.LoadRequestsFromPem(csrBytes)
		if err != nil {
			return err
		}

		signingParams := certutils.SigningParameters{
			SerialNumber: time.Now().UnixNano(),
			NotBefore:    certutils.CertificateNotBefore(),
			NotAfter:     time.Now().Add(CLI.Duration),
		}

		for _, csr := range csrs {
			hosts := []string{}
			if csr.Subject.CommonName != "" {
				hosts = append(hosts)
			}

			hosts = append(hosts, csr.DNSNames...)
			hosts = append(hosts, lo.Map(csr.URIs, func(item *url.URL, index int) string {
				return item.String()
			})...)
			hosts = append(hosts, lo.Map(csr.IPAddresses, func(item net.IP, index int) string {
				return item.String()
			})...)
			hosts = append(hosts, csr.EmailAddresses...)

			l.Debug("Signing CSR for subjects", zap.Strings("subjects", hosts))
			cert, err := certutils.SignCertificate(csr, caCert.Cert, caCert.Key, signingParams)
			if err != nil {
				return err
			}

			if spec.CertificateFile == "" {
				spec.CertificateFile = fmt.Sprintf("%s.%s", certificateNameBuilder(CLI.FilenameConfig, spec.Hosts[0]), CLI.FilenameConfig.CertFileExt)
			}

			certPath := pathlib.NewPath(spec.CertificateFile, pathlib.PathWithAfero(fs))

			certPEMbytes, err := certutils.EncodeCertificates(cert)
			if err != nil {
				return err
			}

			if err := certPath.WriteFile(certPEMbytes); err != nil {
				return err
			}

			l.Info("Wrote certificate", zap.String("cert_path", certPath.String()))
		}
	}
	return nil
}

// csrFromSpec centralizes the CSR generation code and is use by certificate mode and signing mode
func csrFromSpec(ctx context.Context, caConfig ca.CaConfig, commonUsage x509.KeyUsage, commonExtUsage []x509.ExtKeyUsage, keyType certutils.PrivateKeyType, spec certspec.CertSpecification) (*x509.CertificateRequest, interface{}, error) {
	l := zap.L().With(zax.Get(ctx)...)
	// Request the CSR
	csrParams := certutils.CSRParameters{
		KeyUsage: commonUsage | spec.KeyUsage,
		ExtKeyUsage: func() (r []x509.ExtKeyUsage) {
			r = append(r, commonExtUsage...)
			r = append(r, spec.ExtKeyUsage...)
			return lo.Uniq(r)
		}(),
		IsCA: spec.IsCa,
	}

	subject := ca.SubjectFromCaConfig(caConfig)
	// Blank out the subject specific names
	subject.CommonName = ""
	subject.SerialNumber = ""

	l.Debug("Generating new private key", zap.String("key_type", keyType.String()))
	key, err := certutils.GeneratePrivateKey(keyType)
	if err != nil {
		return nil, nil, err
	}

	l.Debug("Generating CSR")
	csr, err := certutils.GenerateCSR(subject, csrParams, key, spec.Hosts...)
	if err != nil {
		return nil, nil, err
	}
	return csr, key, nil
}

func certificateNameBuilder(filenameConfig models.CertificateFilenameConfig, host string) string {
	certFilenameBuilder := []string{}
	certFilenameBuilder = util.AppendIfNotBlank(certFilenameBuilder, filenameConfig.NamePrefix)
	certFilenameBuilder = util.AppendIfNotBlank(certFilenameBuilder, certutils.CommonNameToFileName(host))
	certFilenameBuilder = util.AppendIfNotBlank(certFilenameBuilder, filenameConfig.NameSuffix)

	certBasename := strings.Join(certFilenameBuilder, ".")
	return certBasename
}
