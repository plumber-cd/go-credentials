//go:build darwin && cgo && !ios
// +build darwin,cgo,!ios

package credentials

import (
	"errors"
	"fmt"

	"github.com/keybase/go-keychain"
)

func init() {
	Current = &DarwinProvider{}
}

type DarwinProvider struct {
	domain *Domain
}

func (p *DarwinProvider) ErrorWrap(url string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		return fmt.Errorf("%w: %s: %v", ErrDuplicate, url, err)
	}
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return fmt.Errorf("%w: %s: %v", ErrNotFound, url, err)
	}
	return fmt.Errorf("%w: %s", err, url)
}

func (p *DarwinProvider) SetDomain(domain *Domain) {
	p.domain = domain
}

func (p *DarwinProvider) IsConfigured() bool {
	return p.domain != nil
}

func (p *DarwinProvider) NewCreateItem(url, name, secret string) keychain.Item {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetLabel(p.domain.Service)
	item.SetAccessGroup(p.domain.AccessGroup)
	item.SetAccount(name)
	item.SetService(url)
	item.SetData([]byte(secret))
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	return item
}

func (p *DarwinProvider) Create(url, name, secret string) error {
	item := p.NewCreateItem(url, name, secret)
	err := keychain.AddItem(item)
	return p.ErrorWrap(url, err)
}

func (p *DarwinProvider) NewRetrieveItem(url string) keychain.Item {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetLabel(p.domain.Service)
	item.SetAccessGroup(p.domain.AccessGroup)
	item.SetService(url)
	item.SetMatchLimit(keychain.MatchLimitOne)
	item.SetReturnAttributes(true)
	item.SetReturnData(true)
	return item
}

func (p *DarwinProvider) QueryItem(query keychain.Item) (keychain.QueryResult, error) {
	secret, err := keychain.QueryItem(query)
	if err != nil {
		return keychain.QueryResult{}, err
	} else if len(secret) < 1 {
		return keychain.QueryResult{}, keychain.ErrorItemNotFound
	} else if len(secret) > 1 {
		return keychain.QueryResult{}, keychain.ErrorDuplicateItem
	}
	return secret[0], nil
}

func (p *DarwinProvider) Retrieve(url string) (string, string, error) {
	query := p.NewRetrieveItem(url)
	secret, err := p.QueryItem(query)
	if err != nil {
		return "", "", p.ErrorWrap(url, err)
	}
	return secret.Account, string(secret.Data), nil
}

func (p *DarwinProvider) Update(url, name, secret string) error {
	oldItem := p.NewDeleteItem(url)
	newItem := p.NewCreateItem(url, name, secret)
	return p.ErrorWrap(url, keychain.UpdateItem(oldItem, newItem))
}

func (p *DarwinProvider) NewDeleteItem(url string) keychain.Item {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetLabel(p.domain.Service)
	item.SetAccessGroup(p.domain.AccessGroup)
	item.SetService(url)
	return item
}

func (p *DarwinProvider) Delete(url string) error {
	item := p.NewDeleteItem(url)
	return p.ErrorWrap(url, keychain.DeleteItem(item))
}
