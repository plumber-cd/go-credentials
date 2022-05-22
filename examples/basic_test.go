package examples

import (
	"testing"

	"github.com/plumber-cd/go-credentials"
	"github.com/stretchr/testify/require"
)

func TestBig(t *testing.T) {
	require.True(t, credentials.IsDefined())

	_, _, err := credentials.Retrieve("http://foo")
	require.Error(t, err)
	require.ErrorIs(t, err, credentials.ErrNotConfigured)

	domain := &credentials.Domain{
		Service:     "GoCredentialsTesting",
		AccessGroup: "github.com/plumber-cd/go-credentials/examples",
	}
	require.False(t, credentials.IsConfigured())

	err = credentials.SetDomain(domain)
	require.NoError(t, err)
	require.True(t, credentials.IsConfigured())

	err = credentials.Create("http://foo", "foo", "bar")
	require.NoError(t, err)

	err = credentials.Create("http://foo", "baz", "qwe")
	require.Error(t, err)
	require.ErrorIs(t, err, credentials.ErrDuplicate)

	username, address, err := credentials.Retrieve("http://foo")
	require.NoError(t, err)
	require.Equal(t, "foo", username)
	require.Equal(t, "bar", address)

	_, _, err = credentials.Retrieve("http://bar")
	require.Error(t, err)
	require.ErrorIs(t, err, credentials.ErrNotFound)

	err = credentials.Update("http://foo", "baz", "qwe")
	require.NoError(t, err)
	require.Equal(t, "foo", username)
	require.Equal(t, "bar", address)

	err = credentials.Update("http://bar", "", "")
	require.Error(t, err)
	require.ErrorIs(t, err, credentials.ErrNotFound)

	err = credentials.Delete("http://foo")
	require.NoError(t, err)

	err = credentials.Delete("http://foo")
	require.Error(t, err)
	require.ErrorIs(t, err, credentials.ErrNotFound)

	credentials.Current = nil
	_, _, err = credentials.Retrieve("http://foo")
	require.Error(t, err)
	require.ErrorIs(t, err, credentials.ErrProviderUndefined)
}
