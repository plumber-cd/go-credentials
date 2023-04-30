//go:build windows
// +build windows

package credentials

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/danieljoos/wincred"
)

var (
	ErrorDuplicateItem = errors.New("Secret already existed")
	ErrorItemNotFound  = wincred.ErrElementNotFound
)

func init() {
	Current = &WindowsProvider{}
}

type WindowsProvider struct {
	domain *Domain
}

func (p *WindowsProvider) ErrorWrap(url string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, wincred.ErrElementNotFound) {
		return fmt.Errorf("%w: %s: %v", ErrNotFound, url, err)
	}
	return fmt.Errorf("%w: %s", err, url)
}

func (p *WindowsProvider) SetDomain(domain *Domain) {
	p.domain = domain
}

func (p *WindowsProvider) IsConfigured() bool {
	return p.domain != nil
}

func (p *WindowsProvider) getTargetName(url string) string {
	return p.domain.Service + " (" + url + ")"
}

func (p *WindowsProvider) Create(url, name, secret string) error {
	_, existing, err := p.Retrieve(url)
	if err != nil && !errors.Is(err, ErrNotFound) {
		p.ErrorWrap(url, err)
	}
	if existing != "" {
		return p.ErrorWrap(url, ErrDuplicate)
	}

	g := wincred.NewGenericCredential(p.getTargetName(url))
	g.UserName = name
	g.CredentialBlob = []byte(secret)
	g.Persist = wincred.PersistLocalMachine
	g.Attributes = []wincred.CredentialAttribute{
		{
			Keyword: "url",
			Value:   []byte(url),
		},
		{
			Keyword: "access-group",
			Value:   []byte(p.domain.AccessGroup),
		},
	}

	return g.Write()
}

func (p *WindowsProvider) matchAttributes(url string, g *wincred.GenericCredential) bool {
	matchAccessGroup, matchUrl := false, false
	for _, attr := range g.Attributes {
		if strings.Compare(attr.Keyword, "url") == 0 &&
			bytes.Equal(attr.Value, []byte(url)) {
			matchUrl = true
		}

		if strings.Compare(attr.Keyword, "access-group") == 0 &&
			bytes.Equal(attr.Value, []byte(p.domain.AccessGroup)) {
			matchAccessGroup = true
		}
	}
	return matchUrl && matchAccessGroup
}

func (p *WindowsProvider) Retrieve(url string) (string, string, error) {
	g, err := wincred.GetGenericCredential(p.getTargetName(url))
	if err != nil {
		return "", "", p.ErrorWrap(url, err)
	}
	if g == nil {
		return "", "", p.ErrorWrap(url, ErrNotFound)
	}
	if !(p.matchAttributes(url, g)) {
		return "", "", p.ErrorWrap(url, ErrNotFound)
	}
	return g.UserName, string(g.CredentialBlob), nil
}

func (p *WindowsProvider) Update(url, name, secret string) error {
	if err := p.Delete(url); err != nil {
		return err
	}
	return p.Create(url, name, secret)
}

func (p *WindowsProvider) Delete(url string) error {
	g, err := wincred.GetGenericCredential(p.getTargetName(url))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return p.ErrorWrap(url, err)
	}
	if g == nil {
		return nil
	}
	if !(p.matchAttributes(url, g)) {
		return nil
	}
	return g.Delete()
}
