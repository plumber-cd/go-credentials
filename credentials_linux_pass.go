//go:build linux
// +build linux

package credentials

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
)

type LinuxPassProvider struct {
	domain *Domain
}

type Credentials struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

func (p *LinuxPassProvider) SetDomain(domain *Domain) {
	p.domain = domain
}

func (p *LinuxPassProvider) IsInstalledAndInitialized() bool {
	cmd := exec.Command("pass", "ls")
	if err := cmd.Run(); err != nil {
		return false
	}

	return true
}

func (p *LinuxPassProvider) IsConfigured() bool {
	if p.domain == nil {
		return false
	}

	return p.IsInstalledAndInitialized()
}

func (p *LinuxPassProvider) insert(url, name, secret string) error {
	encodedName := encodeBase64(name)
	encodedSecret := encodeBase64(secret)
	entry := encodedName + ":" + encodedSecret

	cmd := exec.Command("pass", "insert", "--multiline", p.getPassPath(url))
	cmd.Stdin = strings.NewReader(entry)
	err := cmd.Run()
	return p.ErrorWrap(url, err)
}

func (p *LinuxPassProvider) Create(url, name, secret string) error {
	_, _, err := p.Retrieve(url)
	if err == nil {
		// No error means the entry exists
		return ErrDuplicate
	}

	return p.insert(url, name, secret)
}

func (p *LinuxPassProvider) Retrieve(url string) (name, secret string, err error) {
	cmd := exec.Command("pass", p.getPassPath(url))
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return "", "", p.ErrorWrap(url, err)
	}

	parts := strings.SplitN(out.String(), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid entry format")
	}

	name, err = decodeBase64(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("username can't be decoded:", err)
	}
	secret, err = decodeBase64(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("secret can't be decoded:", err)
	}

	return name, secret, nil
}

func (p *LinuxPassProvider) Update(url, name, secret string) error {
	return p.insert(url, name, secret) // In 'pass', create and update are the same
}

func (p *LinuxPassProvider) Delete(url string) error {
	cmd := exec.Command("pass", "rm", "--force", p.getPassPath(url))
	err := cmd.Run()
	return p.ErrorWrap(url, err)
}

func (p *LinuxPassProvider) ErrorWrap(url string, err error) error {
	if err == nil {
		return nil
	}

	// Interpret errors based on command execution and output
	if execErr, ok := err.(*exec.ExitError); ok {
		stdErr := string(execErr.Stderr)
		switch {
		case strings.Contains(stdErr, "is not in the password store"):
			return fmt.Errorf("%w: %s - %s", ErrNotFound, url, err)
		case strings.Contains(stdErr, "already exists"):
			return fmt.Errorf("%w: %s - %s", ErrDuplicate, url, err)
		default:
			return err
		}
	}

	// For other errors, return as is
	return err
}

// getPassPath generates a path for the pass entry.
func (p *LinuxPassProvider) getPassPath(url string) string {
	hash := md5.Sum([]byte(url))
	hashedURL := hex.EncodeToString(hash[:])
	return fmt.Sprintf("%s/%s/%s", p.domain.Service, p.domain.AccessGroup, hashedURL)
}
