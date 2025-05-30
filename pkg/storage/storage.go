package storage

import (
	"errors"
	"os"

	"github.com/chigopher/pathlib"
	"github.com/wrouesnel/certutils"
	"go.uber.org/zap"
)

func GenerateOrLoadPrivateKey(keyType certutils.PrivateKeyType, keyPath *pathlib.Path) (interface{}, error) {
	l := zap.L()
	var privateKey interface{}
	if exists, err := keyPath.Exists(); err != nil {
		l.Error("Filesystem access error", zap.Error(err))
		return nil, err
	} else if !exists {
		l.Info("Generating new key")
		privateKey, err = certutils.GeneratePrivateKey(keyType)
		if err != nil {
			l.Error("Private key generation failed", zap.Error(err))
			return nil, err
		}
		privateKeyBytes, err := certutils.EncodeKeys(privateKey)
		if err != nil {
			l.Error("Encoding private key failed", zap.Error(err))
			return nil, err
		}
		if err := keyPath.WriteFileMode(privateKeyBytes, os.FileMode(0600)); err != nil {
			l.Error("Saving private key failed", zap.Error(err))
			return nil, err
		}
		l.Info("Wrote private key to file")
	} else {
		l.Info("Found existing key")
	}

	l.Debug("Reading private key from file")
	privateKeyBytes, err := keyPath.ReadFile()
	if err != nil {
		l.Error("Loading private key data", zap.Error(err))
		return nil, err
	}

	l.Debug("Parsing private key")
	privateKeys, err := certutils.LoadPrivateKeysFromPem(privateKeyBytes)
	if err != nil {
		l.Error("Parsing private key failed", zap.Error(err))
		return nil, err
	}
	if len(privateKeys) == 0 {
		l.Error("Failed to load a private key from the file")
		return nil, errors.New("failed to load a private key from the written file")
	}
	if len(privateKeys) > 1 {
		l.Error("Got multiple private keys from the file - allowed only one", zap.Int("count", len(privateKeys)))
		return nil, errors.New("cannot have multiple private keys in the written file")
	}

	return privateKeys[0], nil
}
