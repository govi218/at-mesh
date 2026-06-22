package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"gorm.io/gorm"
)

// AtprotoSession stores indigo OAuth session data, serialized as JSON.
type AtprotoSession struct {
	ID        uint   `gorm:"primaryKey"`
	DID       string `gorm:"column:did;uniqueIndex:idx_session;not null"`
	SessionID string `gorm:"column:session_id;uniqueIndex:idx_session;not null"`
	Data      string `gorm:"column:data;type:text;not null"` // JSON-serialized ClientSessionData
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AtprotoAuthState stores indigo OAuth auth request data, serialized as JSON.
type AtprotoAuthState struct {
	ID        uint   `gorm:"primaryKey"`
	State     string `gorm:"column:state;uniqueIndex;not null"`
	Data      string `gorm:"column:data;type:text;not null"` // JSON-serialized AuthRequestData
	CreatedAt time.Time
}

// OidcBridge links indigo's OAuth state to the Headscale OIDC params
// so we can complete the OIDC flow after the PDS callback.
type OidcBridge struct {
	ID                      uint   `gorm:"primaryKey"`
	OAuthState              string `gorm:"column:oauth_state;uniqueIndex;not null"` // indigo's state token
	OidcClientId            string `gorm:"column:oidc_client_id"`
	OidcRedirectUri         string `gorm:"column:oidc_redirect_uri"`
	OidcScope               string `gorm:"column:oidc_scope"`
	OidcState               string `gorm:"column:oidc_state"`
	OidcNonce               string `gorm:"column:oidc_nonce"`
	OidcCodeChallenge       string `gorm:"column:oidc_code_challenge"`
	OidcCodeChallengeMethod string `gorm:"column:oidc_code_challenge_method"`
	Handle                  string `gorm:"column:handle"` // the AT handle the user entered
	CreatedAt               time.Time
}

// OAuthStore implements oauth.ClientAuthStore using GORM/SQLite.
type OAuthStore struct {
	db *gorm.DB
}

var _ oauth.ClientAuthStore = (*OAuthStore)(nil)

func NewOAuthStore(db *gorm.DB) *OAuthStore {
	return &OAuthStore{db: db}
}

func (s *OAuthStore) AutoMigrate() error {
	return s.db.AutoMigrate(&AtprotoSession{}, &AtprotoAuthState{}, &OidcBridge{})
}

func (s *OAuthStore) GetSession(ctx context.Context, did syntax.DID, sessionID string) (*oauth.ClientSessionData, error) {
	var row AtprotoSession
	if err := s.db.Where("did = ? AND session_id = ?", did.String(), sessionID).First(&row).Error; err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}
	var data oauth.ClientSessionData
	if err := json.Unmarshal([]byte(row.Data), &data); err != nil {
		return nil, fmt.Errorf("error unmarshaling session data: %w", err)
	}
	return &data, nil
}

func (s *OAuthStore) SaveSession(ctx context.Context, sess oauth.ClientSessionData) error {
	dataBytes, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("error marshaling session data: %w", err)
	}
	dataStr := string(dataBytes)

	// Upsert
	var row AtprotoSession
	result := s.db.Where("did = ? AND session_id = ?", sess.AccountDID.String(), sess.SessionID).First(&row)
	if result.Error == gorm.ErrRecordNotFound {
		row = AtprotoSession{
			DID:       sess.AccountDID.String(),
			SessionID: sess.SessionID,
			Data:      dataStr,
		}
		return s.db.Create(&row).Error
	}
	if result.Error != nil {
		return result.Error
	}
	return s.db.Model(&row).Update("data", dataStr).Error
}

func (s *OAuthStore) DeleteSession(ctx context.Context, did syntax.DID, sessionID string) error {
	return s.db.Where("did = ? AND session_id = ?", did.String(), sessionID).Delete(&AtprotoSession{}).Error
}

func (s *OAuthStore) GetAuthRequestInfo(ctx context.Context, state string) (*oauth.AuthRequestData, error) {
	var row AtprotoAuthState
	if err := s.db.Where("state = ?", state).First(&row).Error; err != nil {
		return nil, fmt.Errorf("auth request info not found: %w", err)
	}
	var data oauth.AuthRequestData
	if err := json.Unmarshal([]byte(row.Data), &data); err != nil {
		return nil, fmt.Errorf("error unmarshaling auth request data: %w", err)
	}
	return &data, nil
}

func (s *OAuthStore) SaveAuthRequestInfo(ctx context.Context, info oauth.AuthRequestData) error {
	dataBytes, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("error marshaling auth request data: %w", err)
	}
	row := AtprotoAuthState{
		State: info.State,
		Data:  string(dataBytes),
	}
	return s.db.Create(&row).Error
}

func (s *OAuthStore) DeleteAuthRequestInfo(ctx context.Context, state string) error {
	return s.db.Where("state = ?", state).Delete(&AtprotoAuthState{}).Error
}

// --- OidcBridge helpers ---

func (s *OAuthStore) SaveOidcBridge(bridge *OidcBridge) error {
	return s.db.Create(bridge).Error
}

func (s *OAuthStore) GetOidcBridge(oauthState string) (*OidcBridge, error) {
	var bridge OidcBridge
	if err := s.db.Where("oauth_state = ?", oauthState).First(&bridge).Error; err != nil {
		return nil, err
	}
	return &bridge, nil
}

func (s *OAuthStore) DeleteOidcBridge(oauthState string) error {
	return s.db.Where("oauth_state = ?", oauthState).Delete(&OidcBridge{}).Error
}
