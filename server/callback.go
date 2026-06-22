package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/govi218/at-mesh/internal/db"
	"github.com/govi218/at-mesh/oidc"
	"github.com/labstack/echo/v4"
)

// handleATProtoCallback is the OAuth callback endpoint that the PDS redirects
// to after the user authenticates. It calls indigo's ProcessCallback to
// exchange the auth code for an access token, gets the real DID, then
// issues an OIDC code for Headscale.
func (s *Server) handleATProtoCallback(e echo.Context) error {
	ctx := e.Request().Context()

	// Parse callback params
	params := e.QueryParams()

	// Check for error response from PDS
	if errCode := params.Get("error"); errCode != "" {
		s.logger.Error("PDS OAuth callback error", "error", errCode, "description", params.Get("error_description"))
		return s.renderError(e, "Authentication Failed", fmt.Sprintf("The AT Protocol server returned an error: %s", errCode))
	}

	// The state param in the callback is indigo's OAuth state.
	// Use it to look up the OIDC params we saved in the OidcBridge table.
	oauthState := params.Get("state")
	if oauthState == "" {
		return s.renderError(e, "Missing State", "No state parameter in callback.")
	}

	bridge, err := s.oauthStore.GetOidcBridge(oauthState)
	if err != nil {
		s.logger.Error("error looking up OIDC bridge", "state", oauthState, "err", err)
		return s.renderError(e, "Session Expired", "Could not find the original authorization request. Please try again.")
	}

	// Process the callback via indigo — exchanges code for tokens, verifies DID
	sessData, err := s.oauthApp.ProcessCallback(ctx, params)
	if err != nil {
		s.logger.Error("error processing AT Protocol OAuth callback", "err", err)
		return s.renderError(e, "Authentication Failed", fmt.Sprintf("Could not complete authentication: %v", err))
	}

	// We now have the real DID from the AT Protocol
	did := sessData.AccountDID.String()
	s.logger.Info("AT Protocol OAuth successful", "did", did, "handle", bridge.Handle)

	// Issue an OIDC auth code for Headscale, using the real DID as sub
	oidcCode := oidc.GenerateAuthCode()
	authReq := &db.OidcAuthCode{
		Code:                oidcCode,
		ClientId:            bridge.OidcClientId,
		RedirectUri:         bridge.OidcRedirectUri,
		Scope:               bridge.OidcScope,
		State:               bridge.OidcState,
		Nonce:               bridge.OidcNonce,
		CodeChallenge:       bridge.OidcCodeChallenge,
		CodeChallengeMethod: bridge.OidcCodeChallengeMethod,
		Sub:                 did,
		PreferredUsername:   bridge.Handle,
		Email:               "",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := s.db.DB.Create(authReq).Error; err != nil {
		s.logger.Error("error creating OIDC auth request", "err", err)
		return s.renderError(e, "Server Error", "Could not create the authorization request.")
	}

	// Clean up the bridge
	s.oauthStore.DeleteOidcBridge(oauthState)

	// Redirect to Headscale's callback with the OIDC code
	redirectURL := fmt.Sprintf("%s?code=%s", bridge.OidcRedirectUri, oidcCode)
	if bridge.OidcState != "" {
		redirectURL += fmt.Sprintf("&state=%s", bridge.OidcState)
	}

	return e.Redirect(http.StatusSeeOther, redirectURL)
}
