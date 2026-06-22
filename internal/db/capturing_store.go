package db

import (
	"context"
	"sync"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

// CapturingStore wraps a ClientAuthStore and captures the state from the
// most recent SaveAuthRequestInfo call. This lets us retrieve the OAuth
// state that indigo generates internally inside StartAuthFlow.
//
// Since StartAuthFlow is synchronous, the state is captured before
// StartAuthFlow returns. The mutex protects against concurrent requests.
type CapturingStore struct {
	inner     oauth.ClientAuthStore
	mu        sync.Mutex
	lastState string
}

func NewCapturingStore(inner oauth.ClientAuthStore) *CapturingStore {
	return &CapturingStore{inner: inner}
}

func (c *CapturingStore) GetSession(ctx context.Context, did syntax.DID, sessionID string) (*oauth.ClientSessionData, error) {
	return c.inner.GetSession(ctx, did, sessionID)
}

func (c *CapturingStore) SaveSession(ctx context.Context, sess oauth.ClientSessionData) error {
	return c.inner.SaveSession(ctx, sess)
}

func (c *CapturingStore) DeleteSession(ctx context.Context, did syntax.DID, sessionID string) error {
	return c.inner.DeleteSession(ctx, did, sessionID)
}

func (c *CapturingStore) GetAuthRequestInfo(ctx context.Context, state string) (*oauth.AuthRequestData, error) {
	return c.inner.GetAuthRequestInfo(ctx, state)
}

func (c *CapturingStore) SaveAuthRequestInfo(ctx context.Context, info oauth.AuthRequestData) error {
	c.mu.Lock()
	c.lastState = info.State
	c.mu.Unlock()
	return c.inner.SaveAuthRequestInfo(ctx, info)
}

func (c *CapturingStore) DeleteAuthRequestInfo(ctx context.Context, state string) error {
	return c.inner.DeleteAuthRequestInfo(ctx, state)
}

// GetLastState returns the state from the most recent SaveAuthRequestInfo call.
func (c *CapturingStore) GetLastState() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastState
}
