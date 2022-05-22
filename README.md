# go-credentials
Cross Platform Go Credentials Provider

This simple library provides common interface for working with credentials.

By default it uses the following interfaces:

- MacOS: https://github.com/keybase/go-keychain
- Linux: https://github.com/keybase/dbus
- Windows: https://github.com/danieljoos/wincred

You can substitute it with your own interface per platform.

# Example

