package credentials

import "fmt"

var (
	ErrDuplicate         = fmt.Errorf("Duplicate credentials")
	ErrNotFound          = fmt.Errorf("Credentials not found")
	ErrProviderUndefined = fmt.Errorf("Credentials provider for this system was not defined")
	ErrNotConfigured     = fmt.Errorf("Credentials provider was not configured for this system")
)
