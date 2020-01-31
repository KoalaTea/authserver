package oidc

import (
	"context"

	"github.com/koalatea/authserver/ent"
	"github.com/ory/fosite"
)

// OIDCStorage struct to satisfy the interface for fosite
type OIDCStorage struct {
	client ent.Client
}

// CreateOpenIDConnectSession creates an open id connect session
// for a given authorize code. This is relevant for explicit open id connect flow.
func (o *OIDCStorage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	return nil
}

// GetOpenIDConnectSession returns error
// - nil if a session was found,
// - ErrNoSessionFound if no session was found
// - or an arbitrary error if an error occurred.
func (o *OIDCStorage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	return nil, nil
}

// DeleteOpenIDConnectSession removes an open id connect session from the store.
func (o *OIDCStorage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return nil
}
