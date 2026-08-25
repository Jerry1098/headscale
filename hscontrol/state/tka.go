package state

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

var (
	// ErrTKANotEnabled is returned when a Tailnet Lock RPC arrives for a
	// tailnet with no authority.
	ErrTKANotEnabled = errors.New("tailnet lock is not enabled")

	// ErrTKAAlreadyEnabled is returned when init runs against a live lock.
	ErrTKAAlreadyEnabled = errors.New("tailnet lock is already enabled")

	// ErrTKANoPendingGenesis is returned when init/finish arrives without a
	// preceding init/begin.
	ErrTKANoPendingGenesis = errors.New("no pending genesis AUM")

	// ErrTKABadDisablement is returned for an incorrect disablement secret.
	ErrTKABadDisablement = errors.New("incorrect disablement secret")
)

// tkaStore holds the tailnet's Tailnet Lock state. The in-memory chonk is the
// working copy; every mutation is written through to the database.
//
// ponytail: one mutex for the whole subsystem. Mutations are rare admin
// actions; split it only if lock RPCs ever show up in a profile.
type tkaStore struct {
	mu     sync.Mutex
	chonk  *tka.Mem
	auth   *tka.Authority // nil when the lock is off or disabled
	secret []byte         // disablement secret, set once disabled

	// info is the published [tailcfg.TKAInfo], recomputed on every mutation so
	// that map builds never take mu. Treat a loaded value as immutable: it is
	// shared by every concurrent MapResponse.
	info atomic.Pointer[tailcfg.TKAInfo]

	// pending holds the genesis AUM between init/begin and init/finish, so a
	// client that dies mid-flow leaves no lock behind.
	pending *tka.AUM
}

func loadTKAStore(db *hsdb.HSDatabase) (*tkaStore, error) {
	s := &tkaStore{chonk: tka.ChonkMem()}

	row, err := db.GetTKAState()
	if err != nil {
		return nil, err
	}

	if row == nil {
		return s, nil
	}

	aums := make([]tka.AUM, len(row.AUMs))
	for i, b := range row.AUMs {
		err := aums[i].Unserialize(b)
		if err != nil {
			return nil, fmt.Errorf("decoding stored AUM %d: %w", i, err)
		}
	}

	if len(aums) > 0 {
		err := s.chonk.CommitVerifiedAUMs(aums)
		if err != nil {
			return nil, fmt.Errorf("loading stored AUMs: %w", err)
		}
	}

	if row.LastActiveAncestor != "" {
		var h tka.AUMHash

		err := h.UnmarshalText([]byte(row.LastActiveAncestor))
		if err != nil {
			return nil, fmt.Errorf("decoding last active ancestor: %w", err)
		}

		err = s.chonk.SetLastActiveAncestor(h)
		if err != nil {
			return nil, err
		}
	}

	if len(row.DisablementSecret) > 0 {
		s.secret = row.DisablementSecret
		s.refreshInfoLocked()

		return s, nil
	}

	if len(aums) > 0 {
		s.auth, err = tka.Open(s.chonk)
		if err != nil {
			return nil, fmt.Errorf("opening tka authority: %w", err)
		}
	}

	s.refreshInfoLocked()

	return s, nil
}

// persistLocked writes the in-memory chonk to the database. mu must be held.
//
// ponytail: whole-blob rewrite, O(chain) per mutation. Swap in a GORM-backed
// tka.Chonk if a tailnet ever accumulates thousands of AUMs.
func (s *tkaStore) persistLocked(db *hsdb.HSDatabase) error {
	hashes, err := s.chonk.AllAUMs()
	if err != nil {
		return err
	}

	row := &types.TKAState{
		AUMs:              make([][]byte, 0, len(hashes)),
		DisablementSecret: s.secret,
	}

	for _, h := range hashes {
		aum, err := s.chonk.AUM(h)
		if err != nil {
			return fmt.Errorf("reading AUM %v: %w", h, err)
		}

		row.AUMs = append(row.AUMs, aum.Serialize())
	}

	anc, err := s.chonk.LastActiveAncestor()
	if err == nil && anc != nil {
		row.LastActiveAncestor = anc.String()
	}

	return db.SaveTKAState(row)
}

// refreshInfoLocked republishes the cached [tailcfg.TKAInfo]. mu must be held.
// Call it wherever auth, secret, or the head can move — TKASyncSend moves the
// head without touching auth.
func (s *tkaStore) refreshInfoLocked() {
	switch {
	case s.auth != nil:
		s.info.Store(&tailcfg.TKAInfo{Head: s.auth.Head().String()})
	case s.secret != nil:
		s.info.Store(&tailcfg.TKAInfo{Disabled: true})
	default:
		s.info.Store(nil)
	}
}

// TKAInfo returns the value for [tailcfg.MapResponse.TKAInfo], or nil when the
// tailnet has never enabled Tailnet Lock. The returned value is shared and must
// not be mutated.
func (s *State) TKAInfo() *tailcfg.TKAInfo {
	return s.tka.info.Load()
}

// TKAEnabled reports whether the tailnet has a live Tailnet Lock authority.
func (s *State) TKAEnabled() bool {
	s.tka.mu.Lock()
	defer s.tka.mu.Unlock()

	return s.tka.auth != nil
}

// TKAInitBegin records the genesis AUM a node proposes. It is deliberately not
// committed until TKAInitFinish arrives.
func (s *State) TKAInitBegin(genesis tka.AUM) error {
	s.tka.mu.Lock()
	defer s.tka.mu.Unlock()

	if s.tka.auth != nil {
		return ErrTKAAlreadyEnabled
	}

	s.tka.pending = &genesis

	return nil
}

// initFinishAUM commits the pending genesis AUM, enabling the lock.
func (s *State) initFinishAUM() error {
	s.tka.mu.Lock()
	defer s.tka.mu.Unlock()

	if s.tka.auth != nil {
		return ErrTKAAlreadyEnabled
	}

	if s.tka.pending == nil {
		return ErrTKANoPendingGenesis
	}

	// A previous disablement leaves AUMs behind; tka.Bootstrap requires an
	// empty chonk.
	err := s.tka.chonk.RemoveAll()
	if err != nil {
		return fmt.Errorf("clearing previous tka state: %w", err)
	}

	s.tka.secret = nil

	auth, err := tka.Bootstrap(s.tka.chonk, *s.tka.pending)
	if err != nil {
		return fmt.Errorf("bootstrapping authority: %w", err)
	}

	s.tka.auth = auth
	s.tka.pending = nil
	s.tka.refreshInfoLocked()

	return s.tka.persistLocked(s.db)
}

// TKAInitFinish commits the pending genesis AUM and attaches one node-key
// signature per node, enabling the lock.
func (s *State) TKAInitFinish(sigs map[types.NodeID]tkatype.MarshaledSignature) error {
	err := s.initFinishAUM()
	if err != nil {
		return err
	}

	for id, sig := range sigs {
		nv, ok := s.GetNodeByID(id)
		if !ok {
			return fmt.Errorf("%w: %d", ErrNodeNotFound, id)
		}

		// Reject a signature that would lock the node out. tkatest skips this;
		// storing a bad signature means every peer silently drops the node.
		err := s.TKAVerifyNodeKeySignature(nv.NodeKey(), sig)
		if err != nil {
			return fmt.Errorf("signature for node %d: %w", id, err)
		}

		err = s.setNodeKeySignature(id, sig)
		if err != nil {
			return err
		}
	}

	return nil
}

// TKAVerifyNodeKeySignature checks a node-key signature against the authority.
func (s *State) TKAVerifyNodeKeySignature(
	nodeKey key.NodePublic,
	sig tkatype.MarshaledSignature,
) error {
	s.tka.mu.Lock()
	defer s.tka.mu.Unlock()

	if s.tka.auth == nil {
		return ErrTKANotEnabled
	}

	return s.tka.auth.NodeKeyAuthorized(nodeKey, sig)
}

// setNodeKeySignature writes a node-key signature through the NodeStore to the
// database, following the NodeStore-before-database ordering used by every
// other node mutation in this package.
func (s *State) setNodeKeySignature(id types.NodeID, sig tkatype.MarshaledSignature) error {
	n, ok := s.nodeStore.UpdateNode(id, func(node *types.Node) {
		node.NodeKeySignature = sig
	})
	if !ok {
		return fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, id)
	}

	// A node-key signature has no policy relevance, so skip the rescan
	// persistNodeToDB would trigger for every node at init/finish.
	_, err := s.persistNodeRowToDB(n)
	if err != nil {
		return fmt.Errorf("persisting node-key signature: %w", err)
	}

	return nil
}

// TKABootstrap returns the values a node needs to enable or disable Tailnet
// Lock locally: the genesis AUM while enabled, the disablement secret once
// disabled. The client picks whichever it needs.
func (s *State) TKABootstrap() (tkatype.MarshaledAUM, []byte, error) {
	s.tka.mu.Lock()
	defer s.tka.mu.Unlock()

	if s.tka.secret != nil {
		return nil, s.tka.secret, nil
	}

	if s.tka.auth == nil {
		return nil, nil, ErrTKANotEnabled
	}

	// tka.Bootstrap records the genesis hash as the last active ancestor, and
	// a later checkpoint is equally valid to bootstrap from.
	anc, err := s.tka.chonk.LastActiveAncestor()
	if err != nil {
		return nil, nil, err
	}

	if anc == nil {
		return nil, nil, fmt.Errorf("%w: no genesis AUM in storage", ErrTKANotEnabled)
	}

	aum, err := s.tka.chonk.AUM(*anc)
	if err != nil {
		return nil, nil, err
	}

	return aum.Serialize(), nil, nil
}

// TKASyncOffer answers a node's sync offer with headscale's own offer and the
// AUMs the node is missing.
func (s *State) TKASyncOffer(nodeOffer tka.SyncOffer) (tka.SyncOffer, []tka.AUM, error) {
	s.tka.mu.Lock()
	defer s.tka.mu.Unlock()

	if s.tka.auth == nil {
		return tka.SyncOffer{}, nil, ErrTKANotEnabled
	}

	ourOffer, err := s.tka.auth.SyncOffer(s.tka.chonk)
	if err != nil {
		return tka.SyncOffer{}, nil, fmt.Errorf("computing sync offer: %w", err)
	}

	missing, err := s.tka.auth.MissingAUMs(s.tka.chonk, nodeOffer)
	if err != nil {
		return tka.SyncOffer{}, nil, fmt.Errorf("computing missing AUMs: %w", err)
	}

	return ourOffer, missing, nil
}

// TKASyncSend applies AUMs a node believes headscale is missing and returns the
// resulting head. tka.Authority.Inform verifies signatures and parentage before
// committing; headscale never resolves forks itself.
func (s *State) TKASyncSend(aums []tka.AUM) (string, error) {
	s.tka.mu.Lock()
	defer s.tka.mu.Unlock()

	if s.tka.auth == nil {
		return "", ErrTKANotEnabled
	}

	if len(aums) > 0 {
		err := s.tka.auth.Inform(s.tka.chonk, aums)
		if err != nil {
			return "", fmt.Errorf("applying AUMs: %w", err)
		}

		s.tka.refreshInfoLocked()

		err = s.tka.persistLocked(s.db)
		if err != nil {
			return "", err
		}
	}

	return s.tka.auth.Head().String(), nil
}

// TKASubmitSignature verifies a node-key signature and attaches it to the node
// whose key it signs. Returns the signed node's ID.
func (s *State) TKASubmitSignature(marshaled tkatype.MarshaledSignature) (types.NodeID, error) {
	var sig tka.NodeKeySignature

	err := sig.Unserialize(marshaled)
	if err != nil {
		return 0, fmt.Errorf("decoding signature: %w", err)
	}

	var signed key.NodePublic

	err = signed.UnmarshalBinary(sig.Pubkey)
	if err != nil {
		return 0, fmt.Errorf("decoding signed node key: %w", err)
	}

	err = s.TKAVerifyNodeKeySignature(signed, marshaled)
	if err != nil {
		return 0, err
	}

	nv, ok := s.GetNodeByNodeKey(signed)
	if !ok {
		return 0, fmt.Errorf("%w: signature is for an unknown node key", ErrNodeNotFound)
	}

	err = s.setNodeKeySignature(nv.ID(), marshaled)
	if err != nil {
		return 0, err
	}

	return nv.ID(), nil
}

// TKAAffectedSigs returns every stored node-key signature authorised by keyID.
// The client rejects the whole response if any entry's authorising key ID
// differs, so filter exactly.
func (s *State) TKAAffectedSigs(keyID tkatype.KeyID) ([]tkatype.MarshaledSignature, error) {
	var out []tkatype.MarshaledSignature

	for _, nv := range s.ListNodes().All() {
		stored := nv.NodeKeySignature().AsSlice()
		if len(stored) == 0 {
			continue
		}

		var sig tka.NodeKeySignature

		err := sig.Unserialize(stored)
		if err != nil {
			return nil, fmt.Errorf("decoding stored signature for node %d: %w", nv.ID(), err)
		}

		sigKeyID, err := sig.UnverifiedAuthorizingKeyID()
		if err != nil {
			return nil, fmt.Errorf("reading key ID for node %d: %w", nv.ID(), err)
		}

		if bytes.Equal(sigKeyID, keyID) {
			out = append(out, stored)
		}
	}

	return out, nil
}

// TKADisable verifies a disablement secret and turns the lock off. The secret
// is retained: a node that was offline during the disable fetches it from
// /bootstrap and verifies it against its own authority before disabling.
//
// Nodes verify the secret themselves; checking it here only stops any node
// forcing a tailnet-wide failed disablement.
func (s *State) TKADisable(secret []byte) error {
	s.tka.mu.Lock()
	defer s.tka.mu.Unlock()

	if s.tka.auth == nil {
		return ErrTKANotEnabled
	}

	if !s.tka.auth.ValidDisablement(secret) {
		return ErrTKABadDisablement
	}

	s.tka.auth = nil
	s.tka.secret = secret
	s.tka.refreshInfoLocked()

	return s.tka.persistLocked(s.db)
}

// TKASignatureNeedsRotation reports whether nv holds a node-key signature that
// signs a different key than newKey, returning the old signature so the client
// can re-sign it with tka.ResignNKS.
func (s *State) TKASignatureNeedsRotation(
	nv types.NodeView,
	newKey key.NodePublic,
) (tkatype.MarshaledSignature, bool) {
	stored := nv.NodeKeySignature().AsSlice()
	if len(stored) == 0 {
		return nil, false
	}

	var sig tka.NodeKeySignature

	err := sig.Unserialize(stored)
	if err != nil {
		return nil, false
	}

	want, err := newKey.MarshalBinary()
	if err != nil {
		return nil, false
	}

	if bytes.Equal(sig.Pubkey, want) {
		return nil, false
	}

	return stored, true
}

// applyTKARegistration copies the Tailnet Lock fields of a registration onto
// node. An absent signature leaves the stored one alone: a restart re-registers
// with the same node key and no signature.
func applyTKARegistration(
	node *types.Node,
	nlKey key.NLPublic,
	sig tkatype.MarshaledSignature,
) {
	node.NLKey = nlKey

	if len(sig) > 0 {
		node.NodeKeySignature = sig
	}
}
