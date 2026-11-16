package sshx

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyPolicy decides what happens when a server is not in known_hosts.
// A key that does not match a recorded one is always refused.
type HostKeyPolicy int

const (
	// HostKeyStrict trusts only hosts already recorded in known_hosts.
	HostKeyStrict HostKeyPolicy = iota
	// HostKeyTrustOnFirstUse records a new host's key, as OpenSSH asks to.
	HostKeyTrustOnFirstUse
)

// DefaultKnownHostsPath returns ~/.ssh/known_hosts.
func DefaultKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

// hostKeyCallback verifies a server against the known_hosts file.
//
// onUnknown, when set, decides about hosts that are not recorded yet and
// receives the host and its SHA256 fingerprint; returning true records it.
// Without it, policy decides.
func hostKeyCallback(path string, policy HostKeyPolicy, onUnknown func(host, fingerprint string) bool) (ssh.HostKeyCallback, error) {
	if path == "" {
		path = DefaultKnownHostsPath()
	}
	if path == "" {
		return nil, errors.New("sshx: no known_hosts path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("sshx: create %s: %w", filepath.Dir(path), err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return nil, fmt.Errorf("sshx: create %s: %w", path, err)
		}
	}

	check, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("sshx: read %s: %w", path, err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := check(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}

		// The host is known but presents another key: never continue.
		if len(keyErr.Want) > 0 {
			return fmt.Errorf(
				"sshx: host key mismatch for %s\n  presented: %s\n  recorded:  %s\n"+
					"the server may have been reinstalled, or someone is intercepting the connection",
				hostname, ssh.FingerprintSHA256(key), fingerprints(keyErr.Want),
			)
		}

		// Unknown host.
		accept := policy == HostKeyTrustOnFirstUse
		if onUnknown != nil {
			accept = onUnknown(hostname, ssh.FingerprintSHA256(key))
		}
		if !accept {
			return fmt.Errorf(
				"sshx: unknown host %s with key %s; add it to %s to trust it",
				hostname, ssh.FingerprintSHA256(key), path,
			)
		}
		return appendKnownHost(path, hostname, key)
	}, nil
}

// appendKnownHost records a host and its key in the known_hosts file.
func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("sshx: open %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("sshx: record host %s: %w", hostname, err)
	}
	return nil
}

func fingerprints(keys []knownhosts.KnownKey) string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, ssh.FingerprintSHA256(k.Key))
	}
	return strings.Join(out, ", ")
}
