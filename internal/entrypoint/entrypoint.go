package entrypoint

import (
	"context"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wrouesnel/certutils"
	"github.com/wrouesnel/ctxstdio"
	"github.com/wrouesnel/makecerts/pkg/ca"
	"github.com/wrouesnel/makecerts/pkg/certspec"
	"github.com/wrouesnel/makecerts/pkg/models"
	"github.com/wrouesnel/makecerts/version"

	"github.com/pkg/errors"

	"github.com/alecthomas/kong"
	"go.uber.org/zap/zapcore"

	"go.uber.org/zap"
)

var ErrNotCertificateAuthority = errors.New("Certificate is not a CA certificate")
var ErrMultipleCSRPerFile = errors.New("Multiple certificate requests found in one file")
var ErrNoCSRFound = errors.New("No CSR request found in specified file")
var ErrNilCSR = errors.New("nil CSR passed to loadCSR")

const CertPermissions = 0644
const KeyPermissions = 0600

//nolint:gochecknoglobals
var CLI struct {
	Version kong.VersionFlag `env:"-" help:"Show version number"`
	Logging struct {
		Level  string `default:"info"    help:"logging level"`
		Format string `default:"console" enum:"console,json"  help:"logging format (${enum})"`
	} `embed:"" prefix:"log-"`

	Defaults       bool                             `default:"true"                                                        help:"Apply default certificate extensions if none specified"     negatable:""`
	PrivateKeyType certutils.PrivateKeyType         `default:"ecp256"                                                      enum:"${privatekeytypes}"                                         help:"Private Key Type (${privatekeytypes})"`
	FilenameConfig models.CertificateFilenameConfig `embed:""`
	Ca             ca.CaConfig                      `embed:""                                                              prefix:"ca-"`
	Duration       time.Duration                    `default:"9552h"                                                       help:"Duration in days that certificate is valid for"`
	Usage          []certutils.X509KeyUsage         `enum:"${usages}"                                                      help:"usage to be applied to all generated certificates"`
	ExtendedUsage  []certutils.X509ExtKeyUsage      `enum:"${extendedusages}"                                              help:"extended usage to be applied to all generated certificates"`
	CommonSans     []string                         `help:"List of subject alt-names to add to all generated certificates"`
	CaMode         ca.CaMode                        `default:"generate"                                                    enum:"${camodes}"                                                 help:"CA certificate mode (${camodes})"`
	NoStdin        bool                             `help:"Don't read hostnames from stdin"`
	Commands       []string                         `arg:""                                                                help:"certificate, sign, request"                                 sep:"none"`
}

func Entrypoint(stdOut io.Writer, stdErr io.Writer, stdIn io.ReadCloser) error {
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	var configDirs []string
	deferredLogs := []string{}

	// Command line parsing can now happen
	vars := kong.Vars{"version": version.Version}
	vars["privatekeytypes"] = strings.Join(certutils.PrivateKeyTypeNames(), ",")
	vars["camodes"] = strings.Join(ca.CaModeNames(), ",")
	vars["usages"] = strings.Join(certspec.Usages(), ",")
	vars["extendedusages"] = strings.Join(certspec.ExtUsages(), ",")
	_ = kong.Parse(&CLI,
		kong.Description(version.Description),
		kong.DefaultEnvars(version.Name),
		vars)

	// Initialize logging as soon as possible
	logConfig := zap.NewProductionConfig()
	if err := logConfig.Level.UnmarshalText([]byte(CLI.Logging.Level)); err != nil {
		deferredLogs = append(deferredLogs, err.Error())
	}
	logConfig.Encoding = CLI.Logging.Format
	logConfig.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	if CLI.Logging.Format == "console" {
		logConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	logger, err := logConfig.Build()
	if err != nil {
		// Error unhandled since this is a very early failure
		_, _ = io.WriteString(stdErr, "Failure while building logger")
		return err
	}

	logger.Debug("Configuring signal handling")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	sigCtx, cancelFn := context.WithCancel(appCtx)
	go func() {
		sig := <-sigCh
		logger.Info("Caught signal - exiting", zap.String("signal", sig.String()))
		cancelFn()
		stdIn.Close()
		logger.Warn("Stdin Closed")
	}()

	// Install as the global logger
	zap.ReplaceGlobals(logger)

	// Emit deferred logs
	logger.Info("Using config paths", zap.Strings("configDirs", configDirs))
	for _, line := range deferredLogs {
		logger.Error(line)
	}
	ctx := ctxstdio.Set(sigCtx, stdOut, stdErr, stdIn)

	if err := MakeCerts(ctx); err != nil {
		logger.Error("Error", zap.Error(err))
	}
	return err
}
