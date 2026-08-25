package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// tkaTestServer builds a Headscale with one registered node and a noiseServer
// whose machine key matches it.
func tkaTestServer(t *testing.T) (*noiseServer, types.NodeView) {
	t.Helper()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("tka-user")
	node := putTestNodeInStore(t, app, user, "tka-node")

	nv, ok := app.state.GetNodeByID(node.ID)
	require.True(t, ok)

	return &noiseServer{headscale: app, machineKey: node.MachineKey}, nv
}

// tkaAddNode registers another node in the same tailnet.
func tkaAddNode(t *testing.T, ns *noiseServer, hostname string) types.NodeView {
	t.Helper()

	user := ns.headscale.state.CreateUserForTest("tka-user-" + hostname)
	node := putTestNodeInStore(t, ns.headscale, user, hostname)

	nv, ok := ns.headscale.state.GetNodeByID(node.ID)
	require.True(t, ok)

	return nv
}

func tkaGet(t *testing.T, h http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(body))

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://unused/machine/tka/x",
		&buf,
	)
	rec := httptest.NewRecorder()
	h(rec, req)

	return rec
}

// tkaGenesis builds a genesis AUM trusting a fresh Tailnet Lock key, the way
// `tailscale lock init` does, and returns the key and disablement secret.
func tkaGenesis(t *testing.T) (key.NLPrivate, tka.AUM, []byte) {
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

// tkaSignNodeKey signs nodeKey with nlPriv, as `tailscale lock sign` does.
func tkaSignNodeKey(
	t *testing.T,
	nlPriv key.NLPrivate,
	nodeKey key.NodePublic,
	rotation key.NLPublic,
) tkatype.MarshaledSignature {
	t.Helper()

	nk, err := nodeKey.MarshalBinary()
	require.NoError(t, err)

	sig := tka.NodeKeySignature{
		SigKind: tka.SigDirect,
		KeyID:   nlPriv.KeyID(),
		Pubkey:  nk,
	}

	if !rotation.IsZero() {
		sig.WrappingPubkey = rotation.Verifier()
	}

	sig.Signature, err = nlPriv.SignNKS(sig.SigHash())
	require.NoError(t, err)

	return sig.Serialize()
}

// tkaInitLock runs init/begin + init/finish against ns, enabling the lock, and
// returns the trusted Tailnet Lock key plus the disablement secret.
func tkaInitLock(t *testing.T, ns *noiseServer, nv types.NodeView) (key.NLPrivate, []byte) {
	t.Helper()

	nlPriv, genesis, secret := tkaGenesis(t)

	rec := tkaGet(t, ns.TKAInitBeginHandler, tailcfg.TKAInitBeginRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    nv.NodeKey(),
		GenesisAUM: genesis.Serialize(),
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var beginResp tailcfg.TKAInitBeginResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &beginResp))

	sigs := map[tailcfg.NodeID]tkatype.MarshaledSignature{}
	for _, info := range beginResp.NeedSignatures {
		sigs[info.NodeID] = tkaSignNodeKey(t, nlPriv, info.NodePublic, key.NLPublic{})
	}

	rec = tkaGet(t, ns.TKAInitFinishHandler, tailcfg.TKAInitFinishRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    nv.NodeKey(),
		Signatures: sigs,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	return nlPriv, secret
}

func TestTKAInitBeginRejectsForeignNodeKey(t *testing.T) {
	ns, _ := tkaTestServer(t)

	rec := tkaGet(t, ns.TKAInitBeginHandler, tailcfg.TKAInitBeginRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: key.NewNode().Public(), // not this Noise session's node
	})

	require.NotEqual(t, http.StatusOK, rec.Code,
		"an unregistered node key must not be able to initialise the lock")
}

func TestTKAInitRoundTrip(t *testing.T) {
	ns, nv := tkaTestServer(t)

	nlPriv, genesis, _ := tkaGenesis(t)

	rec := tkaGet(t, ns.TKAInitBeginHandler, tailcfg.TKAInitBeginRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    nv.NodeKey(),
		GenesisAUM: genesis.Serialize(),
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var beginResp tailcfg.TKAInitBeginResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &beginResp))
	require.Len(t, beginResp.NeedSignatures, 1)
	require.Equal(t, nv.NodeKey(), beginResp.NeedSignatures[0].NodePublic)

	// Lock must still be off between begin and finish.
	require.Nil(t, ns.headscale.state.TKAInfo())

	sigs := map[tailcfg.NodeID]tkatype.MarshaledSignature{}
	for _, info := range beginResp.NeedSignatures {
		sigs[info.NodeID] = tkaSignNodeKey(t, nlPriv, info.NodePublic, key.NLPublic{})
	}

	rec = tkaGet(t, ns.TKAInitFinishHandler, tailcfg.TKAInitFinishRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    nv.NodeKey(),
		Signatures: sigs,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	info := ns.headscale.state.TKAInfo()
	require.NotNil(t, info)
	require.Equal(t, genesis.Hash().String(), info.Head)

	updated, ok := ns.headscale.state.GetNodeByID(nv.ID())
	require.True(t, ok)
	require.NotZero(t, updated.NodeKeySignature().Len(),
		"init/finish must attach the signature to the node")

	rec = tkaGet(t, ns.TKABootstrapHandler, tailcfg.TKABootstrapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nv.NodeKey(),
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var boot tailcfg.TKABootstrapResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &boot))
	require.Equal(t, []byte(genesis.Serialize()), []byte(boot.GenesisAUM))
}

func TestTKASyncAppliesAUM(t *testing.T) {
	ns, nv := tkaTestServer(t)
	nlPriv, _ := tkaInitLock(t, ns, nv)

	before := ns.headscale.state.TKAInfo().Head

	// Build an AddKey AUM the way `tailscale lock add` does: open an authority
	// over the same chain and use its updater.
	newKey := key.NewNLPrivate().Public()

	genesis, _, err := ns.headscale.state.TKABootstrap()
	require.NoError(t, err)

	var g tka.AUM
	require.NoError(t, g.Unserialize(genesis))

	chonk := tka.ChonkMem()
	auth, err := tka.Bootstrap(chonk, g)
	require.NoError(t, err)

	updater := auth.NewUpdater(nlPriv)
	require.NoError(t, updater.AddKey(tka.Key{
		Kind:   tka.Key25519,
		Votes:  1,
		Public: newKey.Verifier(),
	}))

	aums, err := updater.Finalize(chonk)
	require.NoError(t, err)
	require.NotEmpty(t, aums)

	marshaled := make([]tkatype.MarshaledAUM, len(aums))
	for i := range aums {
		marshaled[i] = aums[i].Serialize()
	}

	rec := tkaGet(t, ns.TKASyncSendHandler, tailcfg.TKASyncSendRequest{
		Version:     tailcfg.CurrentCapabilityVersion,
		NodeKey:     nv.NodeKey(),
		Head:        aums[len(aums)-1].Hash().String(),
		MissingAUMs: marshaled,
		Interactive: true,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var sendResp tailcfg.TKASyncSendResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &sendResp))
	require.NotEqual(t, before, sendResp.Head, "head must advance")
	require.Equal(t, sendResp.Head, ns.headscale.state.TKAInfo().Head)

	// A node still at the old head must be offered the AUM it is missing.
	rec = tkaGet(t, ns.TKASyncOfferHandler, tailcfg.TKASyncOfferRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nv.NodeKey(),
		Head:    before,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var offerResp tailcfg.TKASyncOfferResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &offerResp))
	require.Equal(t, sendResp.Head, offerResp.Head)
	require.NotEmpty(t, offerResp.MissingAUMs)
}

func TestTKASignStoresSignature(t *testing.T) {
	ns, nv := tkaTestServer(t)
	nlPriv, _ := tkaInitLock(t, ns, nv)

	// Register a second node and sign it.
	other := tkaAddNode(t, ns, "second")
	sig := tkaSignNodeKey(t, nlPriv, other.NodeKey(), key.NLPublic{})

	rec := tkaGet(t, ns.TKASignHandler, tailcfg.TKASubmitSignatureRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   nv.NodeKey(),
		Signature: sig,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	updated, ok := ns.headscale.state.GetNodeByID(other.ID())
	require.True(t, ok)
	require.Equal(t, []byte(sig), []byte(updated.NodeKeySignature().AsSlice()))
}

func TestTKASignRejectsUntrustedSignature(t *testing.T) {
	ns, nv := tkaTestServer(t)
	tkaInitLock(t, ns, nv)

	other := tkaAddNode(t, ns, "second")

	// Signed by a key the authority does not trust.
	rogue := key.NewNLPrivate()
	sig := tkaSignNodeKey(t, rogue, other.NodeKey(), key.NLPublic{})

	rec := tkaGet(t, ns.TKASignHandler, tailcfg.TKASubmitSignatureRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   nv.NodeKey(),
		Signature: sig,
	})
	require.NotEqual(t, http.StatusOK, rec.Code,
		"a signature from an untrusted key must be rejected, not stored and "+
			"then silently rejected by every peer")

	updated, ok := ns.headscale.state.GetNodeByID(other.ID())
	require.True(t, ok)
	require.Zero(t, updated.NodeKeySignature().Len())
}

func TestTKAAffectedSigsFiltersExactly(t *testing.T) {
	ns, nv := tkaTestServer(t)
	nlPriv, _ := tkaInitLock(t, ns, nv)

	got := tkaGet(t, ns.TKAAffectedSigsHandler, tailcfg.TKASignaturesUsingKeyRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nv.NodeKey(),
		KeyID:   nlPriv.KeyID(),
	})
	require.Equal(t, http.StatusOK, got.Code, got.Body.String())

	var resp tailcfg.TKASignaturesUsingKeyResponse
	require.NoError(t, json.Unmarshal(got.Body.Bytes(), &resp))
	require.Len(t, resp.Signatures, 1, "the node signed during init")

	// The client errors out on any signature whose authorising key ID differs
	// from the one it asked for, so an unrelated key must return nothing.
	other := tkaGet(t, ns.TKAAffectedSigsHandler, tailcfg.TKASignaturesUsingKeyRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nv.NodeKey(),
		KeyID:   key.NewNLPrivate().KeyID(),
	})
	require.Equal(t, http.StatusOK, other.Code)

	var emptyResp tailcfg.TKASignaturesUsingKeyResponse
	require.NoError(t, json.Unmarshal(other.Body.Bytes(), &emptyResp))
	require.Empty(t, emptyResp.Signatures)
}

func TestTKADisable(t *testing.T) {
	ns, nv := tkaTestServer(t)
	_, secret := tkaInitLock(t, ns, nv)

	bad := tkaGet(t, ns.TKADisableHandler, tailcfg.TKADisableRequest{
		Version:           tailcfg.CurrentCapabilityVersion,
		NodeKey:           nv.NodeKey(),
		DisablementSecret: bytes.Repeat([]byte{0xAA}, 32),
	})
	require.NotEqual(t, http.StatusOK, bad.Code,
		"a wrong disablement secret must not disable the tailnet")
	require.False(t, ns.headscale.state.TKAInfo().Disabled)

	ok := tkaGet(t, ns.TKADisableHandler, tailcfg.TKADisableRequest{
		Version:           tailcfg.CurrentCapabilityVersion,
		NodeKey:           nv.NodeKey(),
		DisablementSecret: secret,
	})
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())

	info := ns.headscale.state.TKAInfo()
	require.NotNil(t, info)
	require.True(t, info.Disabled)
	require.Empty(t, info.Head)

	// A node that was offline during the disable must still be able to fetch
	// the secret and verify it locally.
	rec := tkaGet(t, ns.TKABootstrapHandler, tailcfg.TKABootstrapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nv.NodeKey(),
	})
	require.Equal(t, http.StatusOK, rec.Code)

	var boot tailcfg.TKABootstrapResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &boot))
	require.Equal(t, secret, boot.DisablementSecret)
}

// TestRegisterReturnsOldSignatureForRotation covers the node-key rotation
// handshake: a re-registering node gets its old signature back so it can
// re-sign it (tka.ResignNKS), and the retry with the rotated signature is
// stored without asking again — the client loops if we ask twice.
func TestRegisterReturnsOldSignatureForRotation(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("rotation-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey1 := key.NewNode()
	nodeNL := key.NewNLPrivate() // the node's own Tailnet Lock key

	_, err = app.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey1.Public(),
		NLKey:    nodeNL.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "rotating-node"},
	}, machineKey.Public())
	require.NoError(t, err)

	node, ok := app.state.GetNodeByNodeKey(nodeKey1.Public())
	require.True(t, ok)
	require.Equal(t, nodeNL.Public(), node.NLKey(),
		"registration must capture the node's rotation key")

	// Enable the lock with a signature over nodeKey1 that wraps the node's own
	// key, which is what makes rotation possible without an admin.
	nlPriv, genesis, _ := tkaGenesis(t)
	require.NoError(t, app.state.TKAInitBegin(genesis))

	oldSig := tkaSignNodeKey(t, nlPriv, nodeKey1.Public(), nodeNL.Public())
	require.NoError(t, app.state.TKAInitFinish(
		map[types.NodeID]tkatype.MarshaledSignature{node.ID(): oldSig},
	))

	// The client rotates its node key and does not know it needs a signature.
	nodeKey2 := key.NewNode()
	rotateReq := tailcfg.RegisterRequest{
		Auth:       &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		OldNodeKey: nodeKey1.Public(),
		NodeKey:    nodeKey2.Public(),
		NLKey:      nodeNL.Public(),
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "rotating-node"},
	}

	resp, err := app.handleRegister(context.Background(), rotateReq, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, []byte(oldSig), []byte(resp.NodeKeySignature),
		"the client needs the old signature to re-sign it")

	// The node key must not have rotated while the signature is missing.
	_, ok = app.state.GetNodeByNodeKey(nodeKey1.Public())
	require.True(t, ok)

	// The retry, as the client does it: ResignNKS over the new node key.
	newSig, err := tka.ResignNKS(nodeNL, nodeKey2.Public(), oldSig)
	require.NoError(t, err)

	rotateReq.NodeKeySignature = newSig

	resp, err = app.handleRegister(context.Background(), rotateReq, machineKey.Public())
	require.NoError(t, err)
	require.Empty(t, resp.NodeKeySignature,
		"asking for a signature again makes the client loop")

	rotated, ok := app.state.GetNodeByNodeKey(nodeKey2.Public())
	require.True(t, ok)
	require.Equal(t, []byte(newSig), []byte(rotated.NodeKeySignature().AsSlice()),
		"the rotated signature must be stored")
}
