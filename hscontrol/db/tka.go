package db

import (
	"errors"
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// tkaStateID is the primary key of the single tka_state row.
const tkaStateID = 1

// GetTKAState returns the stored Tailnet Lock state, or nil when the tailnet
// has never enabled it.
func (hsdb *HSDatabase) GetTKAState() (*types.TKAState, error) {
	var state types.TKAState

	err := hsdb.DB.First(&state, tkaStateID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil //nolint:nilnil // absent state is not an error
	}

	if err != nil {
		return nil, fmt.Errorf("loading tka state: %w", err)
	}

	return &state, nil
}

// SaveTKAState writes the single tka_state row, creating it if needed.
func (hsdb *HSDatabase) SaveTKAState(state *types.TKAState) error {
	state.ID = tkaStateID

	err := hsdb.DB.Save(state).Error
	if err != nil {
		return fmt.Errorf("saving tka state: %w", err)
	}

	return nil
}
