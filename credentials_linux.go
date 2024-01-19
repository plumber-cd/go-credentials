//go:build linux
// +build linux

package credentials

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/keybase/dbus"
	"github.com/keybase/go-keychain/secretservice"
)

func init() {
	Current = &LinuxProvider{}
	if !isLinuxSecretServiceAvailable() {
		Current = &LinuxPassProvider{}
	}
}

type LinuxProvider struct {
	domain *Domain
}

func isLinuxSecretServiceAvailable() bool {
	// Check if the 'dbus-send' command is available
	_, err := exec.LookPath("dbus-send")
	if err != nil {
		// 'dbus-send' is not installed
		return false
	}

	// Attempt to query the Secret Service API on D-Bus
	cmd := exec.Command("dbus-send", "--print-reply", "--dest=org.freedesktop.DBus",
		"/org/freedesktop/DBus", "org.freedesktop.DBus.NameHasOwner",
		"string:org.freedesktop.secrets")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Error executing dbus-send command
		return false
	}

	// Check if the output indicates that the service is available
	return strings.Contains(string(output), "boolean true")
}

func (p *LinuxProvider) ErrorWrap(url string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s", err, url)
}

func (p *LinuxProvider) SetDomain(domain *Domain) {
	p.domain = domain
}

func (p *LinuxProvider) IsConfigured() bool {
	return p.domain != nil
}

func (p *LinuxProvider) getSecretName(url string) string {
	return p.domain.Service + " (" + url + ")"
}

func (p *LinuxProvider) OpenItem(
	url string,
	callback func(
		*secretservice.SecretService,
		dbus.ObjectPath,
		secretservice.Attributes,
		string,
	) error,
) error {
	srv, err := secretservice.NewService()
	if err != nil {
		return err
	}

	defer func() {
		_ = srv.LockItems([]dbus.ObjectPath{secretservice.DefaultCollection})
	}()
	if err := srv.Unlock([]dbus.ObjectPath{secretservice.DefaultCollection}); err != nil {
		return err
	}

	items, err := srv.SearchCollection(
		secretservice.DefaultCollection,
		map[string]string{
			"access-group": p.domain.AccessGroup,
			"url":          url,
		},
	)
	if err != nil {
		return err
	}

	for _, item := range items {
		attrs, err := srv.GetAttributes(item)
		if err != nil {
			return err
		}
		if slices.Contains(maps.Keys(attrs), "access-group") && attrs["access-group"] == p.domain.AccessGroup && attrs["url"] == url {
			session, err := srv.OpenSession(secretservice.AuthenticationDHAES)
			if err != nil {
				return err
			}

			secret, err := srv.GetSecret(item, *session)
			if err != nil {
				return err
			}
			return callback(srv, item, attrs, string(secret))
		}
	}

	return ErrNotFound
}

func (p *LinuxProvider) Create(url, name, secret string) error {
	if err := p.OpenItem(
		url,
		func(
			_ *secretservice.SecretService,
			_ dbus.ObjectPath,
			_attrs secretservice.Attributes,
			_secret string,
		) error {
			return p.ErrorWrap(url, ErrDuplicate)
		},
	); err != nil && !errors.Is(err, ErrNotFound) {
		return p.ErrorWrap(url, err)
	}

	srv, err := secretservice.NewService()
	if err != nil {
		return p.ErrorWrap(url, err)
	}

	session, err := srv.OpenSession(secretservice.AuthenticationDHAES)
	if err != nil {
		return p.ErrorWrap(url, err)
	}

	s, err := session.NewSecret([]byte(secret))
	if err != nil {
		return p.ErrorWrap(url, err)
	}

	// Do we ever need to lock the collection?
	// defer func() {
	// 	_ = srv.LockItems([]dbus.ObjectPath{secretservice.DefaultCollection})
	// }()
	if err := srv.Unlock([]dbus.ObjectPath{secretservice.DefaultCollection}); err != nil {
		return p.ErrorWrap(url, err)
	}

	_, err = srv.CreateItem(
		secretservice.DefaultCollection,
		secretservice.NewSecretProperties(
			p.getSecretName(url),
			map[string]string{
				"access-group": p.domain.AccessGroup,
				"username":     name,
				"url":          url,
			},
		),
		s,
		secretservice.ReplaceBehaviorDoNotReplace,
	)

	return err
}

func (p *LinuxProvider) Retrieve(url string) (string, string, error) {
	var attrs secretservice.Attributes
	var secret string
	if err := p.OpenItem(
		url,
		func(
			_ *secretservice.SecretService,
			_ dbus.ObjectPath,
			_attrs secretservice.Attributes,
			_secret string,
		) error {
			attrs = _attrs
			secret = _secret
			return nil
		},
	); err != nil {
		return "", "", p.ErrorWrap(url, err)
	}

	return attrs["username"], string(secret), nil
}

func (p *LinuxProvider) Update(url, name, secret string) error {
	if err := p.Delete(url); err != nil {
		return err
	}
	return p.Create(url, name, secret)
}

func (p *LinuxProvider) Delete(url string) error {
	return p.OpenItem(
		url,
		func(
			srv *secretservice.SecretService,
			item dbus.ObjectPath,
			_ secretservice.Attributes,
			_ string,
		) error {
			return p.ErrorWrap(url, srv.DeleteItem(item))
		},
	)
}
