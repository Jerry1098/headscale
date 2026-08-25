package state

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"tailscale.com/tka"
	"tailscale.com/types/key"
)

// newTestGenesis builds a real genesis AUM signed by a fresh Tailnet Lock
// key, the same way `tailscale lock init` does.
func newTestGenesis(t *testing.T) (key.NLPrivate, tka.AUM, []byte) {
	t.Helper()

	nlPriv := key.NewNLPrivate()

	secret := bytes.Repeat([]byte{7}, 32)

	_, genesis, err := tka.Create(tka.ChonkMem(), tka.State{
		Keys: []tka.Key{{
			Kind:   tka.Key25519,
			Votes:  2,
			Public: nlPriv.Public().Verifier(),
		}},
		DisablementValues: [][]byte{tka.DisablementKDF(secret)},
	}, nlPriv)
	require.NoError(t, err)

	return nlPriv, genesis, secret
}

func TestTKAStatePersistsAcrossRestart(t *testing.T) {
	dbPath, s, _ := persistTestSetup(t)

	_, genesis, _ := newTestGenesis(t)

	require.Nil(t, s.TKAInfo(), "lock must be off before init")

	require.NoError(t, s.TKAInitBegin(genesis))
	require.Nil(t, s.TKAInfo(), "begin must not enable the lock")

	require.NoError(t, s.TKAInitFinish(nil))

	head := s.TKAInfo().Head
	require.Equal(t, genesis.Hash().String(), head)

	require.NoError(t, s.Close())

	s2 := persistTestReopen(t, dbPath)

	require.Equal(t, head, s2.TKAInfo().Head, "head must survive a restart")
}
