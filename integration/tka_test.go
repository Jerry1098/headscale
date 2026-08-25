package integration

import (
	"regexp"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	tlPubKeyRe    = regexp.MustCompile(`tlpub:[0-9a-f]+`)
	tlDisableRe   = regexp.MustCompile(`disablement-secret:[0-9A-F]+`)
	tlSignHintRe  = regexp.MustCompile(`tailscale lock sign (nodekey:[0-9a-f]+) (tlpub:[0-9a-f]+)`)
	tlEnabledText = "Tailnet Lock is ENABLED."
)

// lockStatus runs `tailscale lock status` and returns its stdout.
func lockStatus(t *testing.T, client TailscaleClient) string {
	t.Helper()

	out, _, err := client.Execute([]string{"tailscale", "lock", "status"})
	require.NoError(t, err)

	return out
}

// TestTailnetLock drives the whole feature the way an operator does: enable the
// lock from a node, watch every existing node come out signed, add a node that
// is locked out until it is signed, then disable the lock with a disablement
// secret. Unit tests cannot catch a well-formed but wrong relay; only a real
// client can.
func TestTailnetLock(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"alice"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("tailnetlock"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_TAILNET_LOCK_ENABLED": "true",
		}),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	clients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, clients, 2)

	initiator, peer := clients[0], clients[1]

	// Baseline: the two nodes see each other before any lock exists.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := peer.Status()
		assert.NoError(c, err)
		assert.Len(c, status.Peers(), 1)
	}, 30*time.Second, time.Second, "nodes should see each other before the lock")

	// The initiator's own tailnet-lock key must be trusted at init.
	selfKey := tlPubKeyRe.FindString(lockStatus(t, initiator))
	require.NotEmpty(t, selfKey, "lock status must report this node's tailnet-lock key")

	// Mutating: enable the lock. Runs exactly once.
	out, _, err := initiator.Execute([]string{
		"tailscale", "lock", "init", "--confirm", "--gen-disablements", "1", selfKey,
	})
	require.NoError(t, err, "initialising tailnet lock")

	secret := tlDisableRe.FindString(out)
	require.NotEmpty(t, secret, "lock init must print a disablement secret")

	// Both nodes must see the lock and stay signed: init/finish signs every
	// node that existed, so nobody loses connectivity when enforcement starts.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		for _, client := range clients {
			out, _, err := client.Execute([]string{"tailscale", "lock", "status"})
			assert.NoError(c, err)
			assert.Contains(c, out, tlEnabledText)
			assert.Contains(c, out, "This node is accessible under Tailnet Lock")
		}
	}, 120*time.Second, 2*time.Second, "every node should be locked and signed")

	// Signatures actually verify only if traffic still flows.
	err = initiator.Ping(peer.MustIPv4().String())
	require.NoError(t, err, "peers must still reach each other under the lock")

	// A node joining a locked tailnet is locked out until it is signed.
	newUser, err := scenario.CreateUser("bob")
	require.NoError(t, err)

	err = scenario.CreateTailscaleNodesInUser(
		"bob", "unstable", 1,
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	key, err := scenario.CreatePreAuthKey(mustParseID(newUser.Id), true, false)
	require.NoError(t, err)

	err = scenario.RunTailscaleUp("bob", headscale.GetEndpoint(), key.Key)
	require.NoError(t, err)

	joiners, err := scenario.ListTailscaleClients("bob")
	require.NoError(t, err)
	require.Len(t, joiners, 1)

	joiner := joiners[0]

	var nodeKey, rotationKey string

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		out, _, err := joiner.Execute([]string{"tailscale", "lock", "status"})
		assert.NoError(c, err)
		assert.Contains(c, out, "This node is LOCKED OUT by Tailnet Lock")

		if m := tlSignHintRe.FindStringSubmatch(out); m != nil {
			nodeKey, rotationKey = m[1], m[2]
		}

		assert.NotEmpty(c, nodeKey, "status must name the keys to sign")
	}, 120*time.Second, 2*time.Second, "an unsigned node should be locked out")

	// Mutating: sign the new node from a node holding a trusted key.
	_, _, err = initiator.Execute([]string{
		"tailscale", "lock", "sign", nodeKey, rotationKey,
	})
	require.NoError(t, err, "signing the new node")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		out, _, err := joiner.Execute([]string{"tailscale", "lock", "status"})
		assert.NoError(c, err)
		assert.Contains(c, out, "This node is accessible under Tailnet Lock")
	}, 120*time.Second, 2*time.Second, "a signed node should be accepted")

	err = joiner.Ping(initiator.MustIPv4().String())
	require.NoError(t, err, "a signed node must reach its peers")

	// Mutating: disable the lock with the secret from init.
	_, _, err = initiator.Execute([]string{"tailscale", "lock", "disable", secret})
	require.NoError(t, err, "disabling tailnet lock")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		for _, client := range append(clients, joiner) {
			out, _, err := client.Execute([]string{"tailscale", "lock", "status"})
			assert.NoError(c, err)
			assert.Contains(c, out, "Tailnet Lock is NOT enabled.")
		}
	}, 120*time.Second, 2*time.Second, "every node should observe the disablement")
}
