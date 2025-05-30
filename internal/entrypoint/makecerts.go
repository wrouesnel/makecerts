//go:generate go tool go-enum --lower
package entrypoint

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/chigopher/pathlib"
	"github.com/spf13/afero"
	"github.com/wrouesnel/certutils"
	"github.com/wrouesnel/ctxstdio"
	"github.com/wrouesnel/makecerts/pkg/ca"
	"github.com/wrouesnel/makecerts/pkg/certspec"
	"github.com/wrouesnel/makecerts/pkg/models"
	"github.com/wrouesnel/makecerts/pkg/util"
	"github.com/yuseferi/zax/v2"
	"go.uber.org/zap"
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

	l.Debug("Handling CA certificate")
	caCert, err := ca.HandleCACertificate(fs, CLI.FilenameConfig, CLI.Ca, CLI.CaMode, CLI.PrivateKeyType)
	if err != nil {
		return err
	}

	l.Debug("Validating Commands")
	var commandErr error
	var currentOp CertOperations
	ops := map[CertOperations][]certspec.CertSpecification{}
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

	currentOp = CertOperations("")

	if CLI.NoStdin == false {
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

			spec := certspec.CertSpecification{}
			if err := spec.UnmarshalText([]byte(line)); err != nil {
				l.Error("Invalid specificaton", zap.String("line", line), zap.String("error", err.Error()))
				commandErr = ErrCommandErr
			}
			ops[currentOp] = append(ops[currentOp], spec)
		}
	}

	if commandErr != nil {
		return commandErr
	}

	l.Info("Parsed Specifications", zap.Int("certificates", len(ops[CertOperationsCertificate])),
		zap.Int("signatures", len(ops[CertOperationsSign])), zap.Int("csrs", len(ops[CertOperationsRequest])))

	l.Info("Generating requested certificates")
	for _, spec := range ops[CertOperationsCertificate] {
		signingParams := certutils.SigningParameters{
			SerialNumber: time.Now().UnixNano(),
			NotBefore:    certutils.CertificateNotBefore(),
			NotAfter:     time.Now().Add(CLI.Duration),
		}
		l.Debug("Generating new certificate for subjects", zap.Strings("subjects", spec.Hosts))
		cert := certutils.RequestTLSCertificate(caCert.Cert, caCert.Key, signingParams, CLI.PrivateKeyType, spec.Hosts...)
		if cert == nil {
			return ErrCertErr
		}

		if spec.CertificateFile == "" {
			spec.CertificateFile = fmt.Sprintf("%s.%s", certificateNameBuilder(CLI.FilenameConfig, spec.Hosts[0]), CLI.FilenameConfig.CertFileExt)

		}

		if spec.KeyFile == "" {
			spec.KeyFile = fmt.Sprintf("%s.%s", certificateNameBuilder(CLI.FilenameConfig, spec.Hosts[0]), CLI.FilenameConfig.KeyFileExt)
		}

		certPath := pathlib.NewPath(spec.CertificateFile, pathlib.PathWithAfero(fs))
		keyPath := pathlib.NewPath(spec.KeyFile, pathlib.PathWithAfero(fs))

		certPEMbytes, err := certutils.EncodeCertificates(cert.Leaf)
		if err != nil {
			return err
		}

		keyPEMbytes, err := certutils.EncodeKeys(cert.PrivateKey)
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

	//l.Info("Generating requested certificates")
	//for _, spec := range ops[CertOperationsSign] {
	//	l.Debug("Signing CSR for subjects", zap.Strings("subjects", spec.Hosts))
	//}
	//
	//l.Info("Signing CSRs")
	//for _, spec := range ops[CertOperationsRequest] {
	//	l.Debug("Generating CSR for subjects", zap.Strings("subjects", spec.Hosts))
	//}

	return nil
}

func certificateNameBuilder(filenameConfig models.CertificateFilenameConfig, host string) string {
	certFilenameBuilder := []string{}
	certFilenameBuilder = util.AppendIfNotBlank(certFilenameBuilder, filenameConfig.NamePrefix)
	certFilenameBuilder = util.AppendIfNotBlank(certFilenameBuilder, certutils.CommonNameToFileName(host))
	certFilenameBuilder = util.AppendIfNotBlank(certFilenameBuilder, filenameConfig.NameSuffix)

	certBasename := strings.Join(certFilenameBuilder, ".")
	return certBasename
}
