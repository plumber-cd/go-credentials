package credentials

// Domain is the configuration for provider.
// It is used to avoid collisions with other applications.
type Domain struct {
	// Service is a display name or a title for your credentials.
	Service string

	// AccessGroup is a label on your credentials.
	// Some provider implementations will allow you to have multiple credentials for the same URL and Service while they have different Group.
	AccessGroup string
}

// Provider interface is the main CRUD interface for your credentials.
type Provider interface {
	// This has to be called only once per provider instance.
	SetDomain(domain *Domain)

	// Returns true if provider is ready to be used.
	IsConfigured() bool

	// Create creates a new secret. URL is the ultimate key for it.
	Create(url, name, secret string) error

	// Retrieve returns credentials entry by URL.
	Retrieve(url string) (name, secret string, err error)

	// Update finds existing credentials for URL and updates name and secret on it.
	Update(url, name, secret string) error

	// Delete credentials for this URL.
	Delete(url string) error

	// This function should convert downstream libraries errors to common error interfaces.
	ErrorWrap(url string, err error) error
}

var (
	Current Provider
)

func SetDomain(domain *Domain) error {
	if Current == nil {
		return ErrProviderUndefined
	}
	Current.SetDomain(domain)
	return nil
}

func IsDefined() bool {
	return Current != nil
}

func IsConfigured() bool {
	return IsDefined() && Current.IsConfigured()
}

func Create(url, name, secret string) error {
	if !IsDefined() {
		return ErrProviderUndefined
	}
	if !IsConfigured() {
		return ErrNotConfigured
	}
	return Current.Create(url, name, secret)
}

func Retrieve(url string) (name, secret string, err error) {
	if !IsDefined() {
		return "", "", ErrProviderUndefined
	}
	if !IsConfigured() {
		return "", "", ErrNotConfigured
	}
	return Current.Retrieve(url)
}

func Update(url, name, secret string) error {
	if !IsDefined() {
		return ErrProviderUndefined
	}
	if !IsConfigured() {
		return ErrNotConfigured
	}
	return Current.Update(url, name, secret)
}

func Delete(url string) error {
	if !IsDefined() {
		return ErrProviderUndefined
	}
	if !IsConfigured() {
		return ErrNotConfigured
	}
	return Current.Delete(url)
}
