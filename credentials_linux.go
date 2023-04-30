//go:build linux
// +build linux

package credentials

import (
	"errors"
	"fmt"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/keybase/dbus"
	"github.com/keybase/go-keychain/secretservice"
)

func init() {
	Current = &LinuxProvider{}
}

type LinuxProvider struct {
	domain *Domain
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

	defer func() {
		_ = srv.LockItems([]dbus.ObjectPath{secretservice.DefaultCollection})
	}()
	if err := srv.Unlock([]dbus.ObjectPath{secretservice.DefaultCollection}); err != nil {
		return p.ErrorWrap(url, err)
	}

	_, err = srv.CreateItem(
		secretservice.DefaultCollection,
		secretservice.NewSecretProperties(
			p.getSecretName(url),
			map[string]string{
				"access-group": p.domain.AccessGroup,
				"name":         name,
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
		p.getSecretName(url),
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

	return attrs["name"], string(secret), nil
}

func (p *LinuxProvider) Update(url, name, secret string) error {
	if err := p.Delete(url); err != nil {
		return err
	}
	return p.Create(url, name, secret)
}

func (p *LinuxProvider) Delete(url string) error {
	return p.OpenItem(
		p.getSecretName(url),
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
