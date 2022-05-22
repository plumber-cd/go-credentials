# go-credentials
Cross Platform Go Credentials Provider

This simple library provides common interface for working with credentials.

By default it uses the following interfaces:

- MacOS: https://github.com/keybase/go-keychain
- Linux: https://github.com/keybase/dbus
- Windows: https://github.com/danieljoos/wincred

You can substitute it with your own interface per platform.

# Example

```go
package main

import (
    "fmt"

    "github.com/plumber-cd/go-credentials"
)

func main() {
    domain := &credentials.Domain{
		Service:     "My App Name",
		AccessGroup: "github.com/plumber-cd/go-credentials", // Define some unique for your app instance value
	}

	if err := credentials.SetDomain(domain); err != nil {
        panic(err)
    }

    if err := err = credentials.Create("http://example.com", "<name/username/title/display name>", "password"); err != nil {
        panic(err)
    }
    
	name, secret, err := credentials.Retrieve("http://example.com")
    if err != nil {
        panic(err)
    }
    fmt.Printf("Name: %s\n", name)
    fmt.Printf("Secret: %s\n", secret)

	if err := credentials.Update("http://example.com", "new title", "new password"); err != nil {
        panic(err)
    }

	if err := credentials.Delete("http://example.com"); err {
        panic(err)
    }
}
```

# Custom provider

You need to create new `struct` than implements `credentials.Provider` interface. Somewhere early in your app, you then will need to:

```go
package main

import "github.com/plumber-cd/go-credentials"

func main() {
    credentials.Current = &MyCustomProvider{}
}
```

That's it. All other code that is using this same library - will now use your custom provider instead of default.
