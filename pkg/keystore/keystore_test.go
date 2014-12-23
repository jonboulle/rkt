package keystore

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/coreos/rocket/Godeps/_workspace/src/golang.org/x/crypto/openpgp/errors"
	"github.com/coreos/rocket/pkg/keystore/keystoretest"
)

func testKeyStoreConfig() (*Config, error) {
	tempDir, err := ioutil.TempDir("", "keystore-test")
	if err != nil {
		return nil, err
	}
	c := &Config{
		RootPath:         path.Join(tempDir, "/etc/rkt/trustedkeys/root.d"),
		SystemRootPath:   path.Join(tempDir, "/usr/lib/rkt/trustedkeys/root.d"),
		PrefixPath:       path.Join(tempDir, "/etc/rkt/trustedkeys/prefix.d"),
		SystemPrefixPath: path.Join(tempDir, "/usr/lib/rkt/trustedkeys/prefix.d"),
	}
	for _, path := range []string{c.RootPath, c.SystemRootPath, c.PrefixPath, c.SystemPrefixPath} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func removeKeyStore(c *Config) error {
	for _, path := range []string{c.RootPath, c.SystemRootPath, c.PrefixPath, c.SystemPrefixPath} {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

func TestStoreTrustedKey(t *testing.T) {
	armoredPublicKey := keystoretest.KeyMap["example.com"].ArmoredPublicKey
	fingerprint := keystoretest.KeyMap["example.com"].Fingerprint

	keyStoreConfig, err := testKeyStoreConfig()
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	defer removeKeyStore(keyStoreConfig)

	ks := New(keyStoreConfig)

	output, err := ks.StoreTrustedKeyPrefix("example.com/foo", bytes.NewBufferString(armoredPublicKey))
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if filepath.Base(output) != fingerprint {
		t.Errorf("expected finger print %s, got %v", fingerprint, filepath.Base(output))
	}
	if err := ks.DeleteTrustedKeyPrefix("example.com/foo", fingerprint); err != nil {
		t.Errorf("unexpected error %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Errorf("unexpected error %v", err)
	}

	output, err = ks.StoreTrustedKeySystemPrefix("example.com/foo", bytes.NewBufferString(armoredPublicKey))
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if filepath.Base(output) != fingerprint {
		t.Errorf("expected finger print %s, got %v", fingerprint, filepath.Base(output))
	}
	if err := ks.DeleteTrustedKeySystemPrefix("example.com/foo", fingerprint); err != nil {
		t.Errorf("unexpected error %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Errorf("unexpected error %v", err)
	}

	output, err = ks.StoreTrustedKeyRoot(bytes.NewBufferString(armoredPublicKey))
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if filepath.Base(output) != fingerprint {
		t.Errorf("expected finger print %s, got %v", fingerprint, filepath.Base(output))
	}
	if err := ks.DeleteTrustedKeyRoot(fingerprint); err != nil {
		t.Errorf("unexpected error %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Errorf("unexpected error %v", err)
	}

	output, err = ks.StoreTrustedKeySystemRoot(bytes.NewBufferString(armoredPublicKey))
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if filepath.Base(output) != fingerprint {
		t.Errorf("expected finger print %s, got %v", fingerprint, filepath.Base(output))
	}
	if err := ks.DeleteTrustedKeySystemRoot(fingerprint); err != nil {
		t.Errorf("unexpected error %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Errorf("unexpected error %v", err)
	}
}

func TestCheckSignature(t *testing.T) {
	trustedPrefixKeys := []string{
		"docker.com/docker",
		"acme.com/services",
		"acme.com/services/web/nginx",
	}
	trustedRootKeys := []string{
		"coreos.com",
	}
	trustedSystemRootKeys := []string{
		"acme.com",
	}

	keyStoreConfig, err := testKeyStoreConfig()
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	defer removeKeyStore(keyStoreConfig)

	ks := New(keyStoreConfig)
	for _, key := range trustedPrefixKeys {
		if _, err := ks.StoreTrustedKeyPrefix(key, bytes.NewBufferString(keystoretest.KeyMap[key].ArmoredPublicKey)); err != nil {
			t.Fatalf("unexpected error %v", err)
		}
	}
	for _, key := range trustedRootKeys {
		if _, err := ks.StoreTrustedKeyRoot(bytes.NewBufferString(keystoretest.KeyMap[key].ArmoredPublicKey)); err != nil {
			t.Fatalf("unexpected error %v", err)
		}
	}
	for _, key := range trustedSystemRootKeys {
		if _, err := ks.StoreTrustedKeySystemRoot(bytes.NewBufferString(keystoretest.KeyMap[key].ArmoredPublicKey)); err != nil {
			t.Fatalf("unexpected error %v", err)
		}
	}

	// Untrust the acme.com key by writing an empty file.
	err = ioutil.WriteFile(filepath.Join(keyStoreConfig.RootPath, keystoretest.KeyMap["acme.com"].Fingerprint), []byte(""), 0644)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	checkSignatureTests := []struct {
		name    string
		key     string
		trusted bool
	}{
		{"coreos.com/etcd", "coreos.com", true},
		{"coreos.com/fleet", "coreos.com", true},
		{"coreos.com/flannel", "coreos.com", true},
		{"docker.com/docker", "docker.com/docker", true},
		{"acme.com/services/web/nginx", "acme.com/services/web/nginx", true},
		{"acme.com/services/web/auth", "acme.com/services", true},
		{"acme.com/etcd", "acme.com", false},
		{"acme.com/web/nginx", "acme.com", false},
		{"acme.com/services/web", "acme.com/services/web/nginx", false},
	}
	for _, tt := range checkSignatureTests {
		key := keystoretest.KeyMap[tt.key]
		message, signature, err := keystoretest.NewMessageAndSignature(key.ArmoredPrivateKey)
		if err != nil {
			t.Fatalf("unexpected error %v", err)
			continue
		}
		signer, err := ks.CheckSignature(tt.name, message, signature)
		if tt.trusted {
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}
			if signer.PrimaryKey.KeyIdString() != key.Fingerprint {
				t.Errorf("expected fingerprint == %v, got %v", key.Fingerprint, signer.PrimaryKey.KeyIdString())
			}
			continue
		}
		if err == nil {
			t.Errorf("expected ErrUnknownIssuer error")
			continue
		}
		if err.Error() != errors.ErrUnknownIssuer.Error() {
			t.Errorf("unexpected error %v", err)
		}
	}
}
