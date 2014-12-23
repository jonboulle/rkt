// Package keystore implements the ACI keystore.
package keystore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/appc/spec/schema/types"
	"github.com/coreos/rocket/Godeps/_workspace/src/golang.org/x/crypto/openpgp"
)

// A Config structure is used to configure a Keystore.
type Config struct {
	RootPath         string
	PrefixPath       string
	SystemRootPath   string
	SystemPrefixPath string
}

// A Keystore represents a repository of trusted keys which can be used to verify
// ACI images.
type Keystore struct {
	*Config
}

// New returns a new Keystore based on config.
func New(config *Config) *Keystore {
	return &Keystore{config}
}

var defaultConfig = &Config{
	RootPath:         "/etc/rkt/trustedkeys/root.d",
	PrefixPath:       "/etc/rkt/trustedkeys/prefix.d",
	SystemRootPath:   "/usr/lib/rkt/trustedkeys/root.d",
	SystemPrefixPath: "/usr/lib/rkt/trustedkeys/prefix.d",
}

// CheckSignature takes a signed file and a detached signature and returns the signer
// if the signature is signed by a trusted signer.
// If the signer is unknown or not trusted, opengpg.ErrUnknownIssuer is returned.
func CheckSignature(prefix string, signed, signature io.Reader) (*openpgp.Entity, error) {
	ks := New(defaultConfig)
	return checkSignature(ks, prefix, signed, signature)
}

// CheckSignature takes a signed file and a detached signature and returns the signer
// if the signature is signed by a trusted signer.
// If the signer is unknown or not trusted, opengpg.ErrUnknownIssuer is returned.
func (ks *Keystore) CheckSignature(prefix string, signed, signature io.Reader) (*openpgp.Entity, error) {
	return checkSignature(ks, prefix, signed, signature)
}

func checkSignature(ks *Keystore, prefix string, signed, signature io.Reader) (*openpgp.Entity, error) {
	acname, err := types.NewACName(prefix)
	if err != nil {
		return nil, err
	}
	keyring, err := ks.loadKeyring(acname.String())
	if err != nil {
		return nil, err
	}
	return openpgp.CheckArmoredDetachedSignature(keyring, signed, signature)
}

// DeleteTrustedKeyPrefix deletes the prefix trusted key identified by fingerprint.
func (ks *Keystore) DeleteTrustedKeyPrefix(prefix, fingerprint string) error {
	acname, err := types.NewACName(prefix)
	if err != nil {
		return err
	}
	return os.Remove(path.Join(ks.PrefixPath, acname.String(), fingerprint))
}

// DeleteTrustedKeySystemPrefix deletes the system prefix trusted key identified by fingerprint.
func (ks *Keystore) DeleteTrustedKeySystemPrefix(prefix, fingerprint string) error {
	acname, err := types.NewACName(prefix)
	if err != nil {
		return err
	}
	return os.Remove(path.Join(ks.SystemPrefixPath, acname.String(), fingerprint))
}

// DeleteTrustedKeyRoot deletes the root trusted key identified by fingerprint.
func (ks *Keystore) DeleteTrustedKeyRoot(fingerprint string) error {
	return os.Remove(path.Join(ks.RootPath, fingerprint))
}

// DeleteTrustedKeySystemRoot deletes the system root trusted key identified by fingerprint.
func (ks *Keystore) DeleteTrustedKeySystemRoot(fingerprint string) error {
	return os.Remove(path.Join(ks.SystemRootPath, fingerprint))
}

// StoreTrustedKeyPrefix stores the contents of public key r as a prefix trusted key.
func (ks *Keystore) StoreTrustedKeyPrefix(prefix string, r io.Reader) (string, error) {
	acname, err := types.NewACName(prefix)
	if err != nil {
		return "", err
	}
	return storeTrustedKey(path.Join(ks.PrefixPath, acname.String()), r)
}

// StoreTrustedKeySystemPrefix stores the contents of public key r as a system prefix trusted key.
func (ks *Keystore) StoreTrustedKeySystemPrefix(prefix string, r io.Reader) (string, error) {
	acname, err := types.NewACName(prefix)
	if err != nil {
		return "", err
	}
	return storeTrustedKey(path.Join(ks.SystemPrefixPath, acname.String()), r)
}

// StoreTrustedKeyRoot stores the contents of public key r as a root trusted key.
func (ks *Keystore) StoreTrustedKeyRoot(r io.Reader) (string, error) {
	return storeTrustedKey(ks.RootPath, r)
}

// StoreTrustedKeySystemRoot stores the contents of public key r as a system root trusted key.
func (ks *Keystore) StoreTrustedKeySystemRoot(r io.Reader) (string, error) {
	return storeTrustedKey(ks.SystemRootPath, r)
}

func storeTrustedKey(dir string, r io.Reader) (string, error) {
	pubkeyBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(pubkeyBytes))
	if err != nil {
		return "", err
	}
	pubKey := entityList[0].PrimaryKey
	trustedKeyPath := path.Join(dir, pubKey.KeyIdString())
	dest, err := os.OpenFile(trustedKeyPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}
	defer dest.Close()
	_, err = io.Copy(dest, bytes.NewReader(pubkeyBytes))
	if err != nil {
		return "", err
	}
	return trustedKeyPath, nil
}

func entityFromFile(path string) (*openpgp.Entity, error) {
	trustedKey, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer trustedKey.Close()
	entityList, err := openpgp.ReadArmoredKeyRing(trustedKey)
	if err != nil {
		return nil, err
	}
	if len(entityList) < 1 {
		return nil, errors.New("missing opengpg entity")
	}
	if entityList[0].PrimaryKey.KeyIdString() != filepath.Base(trustedKey.Name()) {
		return nil, fmt.Errorf("fingerprint mismatch")
	}
	return entityList[0], nil
}

func (ks *Keystore) loadKeyring(prefix string) (openpgp.KeyRing, error) {
	acname, err := types.NewACName(prefix)
	if err != nil {
		return nil, err
	}
	var keyring openpgp.EntityList
	trustedKeys := make(map[string]*openpgp.Entity)

	prefixRoot := strings.Split(acname.String(), "/")[0]
	paths := []struct {
		root     string
		fullPath string
	}{
		{ks.SystemRootPath, ks.SystemRootPath},
		{ks.RootPath, ks.RootPath},
		{path.Join(ks.SystemPrefixPath, prefixRoot), path.Join(ks.SystemPrefixPath, acname.String())},
		{path.Join(ks.PrefixPath, prefixRoot), path.Join(ks.PrefixPath, acname.String())},
	}
	for _, p := range paths {
		err := filepath.Walk(p.root, func(path string, info os.FileInfo, err error) error {
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if info == nil {
				return nil
			}
			if info.IsDir() {
				switch {
				case strings.HasPrefix(p.fullPath, path):
					return nil
				default:
					return filepath.SkipDir
				}
			}
			// Remove trust for default keys.
			if info.Size() == 0 {
				delete(trustedKeys, info.Name())
				return nil
			}
			entity, err := entityFromFile(path)
			if err != nil {
				return err
			}
			trustedKeys[entity.PrimaryKey.KeyIdString()] = entity
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	for _, v := range trustedKeys {
		keyring = append(keyring, v)
	}
	return keyring, nil
}
