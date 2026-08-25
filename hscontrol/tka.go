package hscontrol

import (
	"encoding/json"
	"net/http"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// writeTKA writes v as the JSON response body, matching the encoding the other
// /machine handlers use.
func writeTKA(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		log.Error().Caller().Err(err).Msg("tka handler: failed to encode response")
	}
}

// tkaReq decodes a TKA request body into req and authenticates the Noise
// session against the node key it names. It writes the error response itself.
func (ns *noiseServer) tkaReq(
	w http.ResponseWriter,
	r *http.Request,
	req any,
	nodeKey *key.NodePublic,
) bool {
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid request", err))

		return false
	}

	_, err = ns.getAndValidateNode(*nodeKey)
	if err != nil {
		httpError(w, err)

		return false
	}

	return true
}

// TKAInitBeginHandler handles GET /machine/tka/init/begin. The genesis AUM is
// held, not committed: the lock only turns on at init/finish, once the
// initiator has signed every existing node.
func (ns *noiseServer) TKAInitBeginHandler(w http.ResponseWriter, r *http.Request) {
	var req tailcfg.TKAInitBeginRequest

	if !ns.tkaReq(w, r, &req, &req.NodeKey) {
		return
	}

	var genesis tka.AUM

	err := genesis.Unserialize(req.GenesisAUM)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid genesis AUM", err))

		return
	}

	err = ns.headscale.state.TKAInitBegin(genesis)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), err))

		return
	}

	// Every node needs a signature before enforcement starts, or it loses
	// connectivity the moment the lock turns on.
	var resp tailcfg.TKAInitBeginResponse

	for _, n := range ns.headscale.state.ListNodes().All() {
		info := tailcfg.TKASignInfo{
			NodeID:     n.ID().NodeID(),
			NodePublic: n.NodeKey(),
		}

		// RotationPubkey lets the node re-sign its own key after rotation
		// without an admin. Omit it rather than send an all-zero key.
		if nl := n.NLKey(); !nl.IsZero() {
			info.RotationPubkey = nl.Verifier()
		}

		resp.NeedSignatures = append(resp.NeedSignatures, info)
	}

	writeTKA(w, resp)
}

// TKAInitFinishHandler handles GET /machine/tka/init/finish.
func (ns *noiseServer) TKAInitFinishHandler(w http.ResponseWriter, r *http.Request) {
	var req tailcfg.TKAInitFinishRequest

	if !ns.tkaReq(w, r, &req, &req.NodeKey) {
		return
	}

	sigs := make(map[types.NodeID]tkatype.MarshaledSignature, len(req.Signatures))
	for id, sig := range req.Signatures {
		sigs[types.NodeID(id)] = sig //nolint:gosec // NodeID types are equivalent
	}

	err := ns.headscale.state.TKAInitFinish(sigs)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), err))

		return
	}

	// Every node's signature and the new head both changed.
	ns.headscale.Change(change.FullUpdate())

	writeTKA(w, tailcfg.TKAInitFinishResponse{})
}

// TKABootstrapHandler handles GET /machine/tka/bootstrap.
func (ns *noiseServer) TKABootstrapHandler(w http.ResponseWriter, r *http.Request) {
	var req tailcfg.TKABootstrapRequest

	if !ns.tkaReq(w, r, &req, &req.NodeKey) {
		return
	}

	genesis, secret, err := ns.headscale.state.TKABootstrap()
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), err))

		return
	}

	writeTKA(w, tailcfg.TKABootstrapResponse{
		GenesisAUM:        genesis,
		DisablementSecret: secret,
	})
}

// TKASyncOfferHandler handles GET /machine/tka/sync/offer.
func (ns *noiseServer) TKASyncOfferHandler(w http.ResponseWriter, r *http.Request) {
	var req tailcfg.TKASyncOfferRequest

	if !ns.tkaReq(w, r, &req, &req.NodeKey) {
		return
	}

	nodeOffer, err := tka.ToSyncOffer(req.Head, req.Ancestors)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid sync offer", err))

		return
	}

	ourOffer, missing, err := ns.headscale.state.TKASyncOffer(nodeOffer)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), err))

		return
	}

	head, ancestors, err := tka.FromSyncOffer(ourOffer)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusInternalServerError, "encoding sync offer", err))

		return
	}

	resp := tailcfg.TKASyncOfferResponse{
		Head:        head,
		Ancestors:   ancestors,
		MissingAUMs: make([]tkatype.MarshaledAUM, len(missing)),
	}

	for i := range missing {
		resp.MissingAUMs[i] = missing[i].Serialize()
	}

	writeTKA(w, resp)
}

// TKASyncSendHandler handles GET /machine/tka/sync/send.
func (ns *noiseServer) TKASyncSendHandler(w http.ResponseWriter, r *http.Request) {
	var req tailcfg.TKASyncSendRequest

	if !ns.tkaReq(w, r, &req, &req.NodeKey) {
		return
	}

	aums := make([]tka.AUM, len(req.MissingAUMs))
	for i, b := range req.MissingAUMs {
		err := aums[i].Unserialize(b)
		if err != nil {
			httpError(w, NewHTTPError(http.StatusBadRequest, "invalid AUM", err))

			return
		}
	}

	head, err := ns.headscale.state.TKASyncSend(aums)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), err))

		return
	}

	if len(aums) > 0 {
		ns.headscale.Change(change.TKAChanged())
	}

	writeTKA(w, tailcfg.TKASyncSendResponse{Head: head})
}

// TKASignHandler handles GET /machine/tka/sign.
func (ns *noiseServer) TKASignHandler(w http.ResponseWriter, r *http.Request) {
	var req tailcfg.TKASubmitSignatureRequest

	if !ns.tkaReq(w, r, &req, &req.NodeKey) {
		return
	}

	signedID, err := ns.headscale.state.TKASubmitSignature(req.Signature)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), err))

		return
	}

	// Peers drop nodes with no valid signature, so the newly signed node must
	// reach every netmap that can see it.
	ns.headscale.Change(
		change.PeersChanged("tailnet lock signature", signedID),
		change.SelfUpdate(signedID),
	)

	writeTKA(w, tailcfg.TKASubmitSignatureResponse{})
}

// TKAAffectedSigsHandler handles GET /machine/tka/affected-sigs.
func (ns *noiseServer) TKAAffectedSigsHandler(w http.ResponseWriter, r *http.Request) {
	var req tailcfg.TKASignaturesUsingKeyRequest

	if !ns.tkaReq(w, r, &req, &req.NodeKey) {
		return
	}

	sigs, err := ns.headscale.state.TKAAffectedSigs(req.KeyID)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusInternalServerError, "reading signatures", err))

		return
	}

	writeTKA(w, tailcfg.TKASignaturesUsingKeyResponse{Signatures: sigs})
}

// TKADisableHandler handles GET /machine/tka/disable.
func (ns *noiseServer) TKADisableHandler(w http.ResponseWriter, r *http.Request) {
	var req tailcfg.TKADisableRequest

	if !ns.tkaReq(w, r, &req, &req.NodeKey) {
		return
	}

	err := ns.headscale.state.TKADisable(req.DisablementSecret)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), err))

		return
	}

	ns.headscale.Change(change.TKAChanged())

	writeTKA(w, tailcfg.TKADisableResponse{})
}
