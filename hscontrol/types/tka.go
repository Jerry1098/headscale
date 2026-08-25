package types

import "time"

// TKAState is the tailnet's Tailnet Lock state. There is at most one row, with
// ID 1. The working copy lives in memory; see hscontrol/state/tka.go.
type TKAState struct {
	ID uint `gorm:"primary_key"`

	// AUMs holds every AUM headscale knows, each tka.AUM.Serialize()'d.
	AUMs [][]byte `gorm:"serializer:json"`

	// LastActiveAncestor is a tka.AUMHash in text form: the hint tka.Open
	// uses to pick a chain when storage holds a fork.
	LastActiveAncestor string

	// DisablementSecret is set once the lock has been disabled, and is served
	// to nodes that were offline at the time.
	DisablementSecret []byte

	CreatedAt time.Time
	UpdatedAt time.Time
}
