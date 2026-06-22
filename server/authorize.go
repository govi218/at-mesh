package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/govi218/at-mesh/internal/db"
	"github.com/govi218/at-mesh/oidc"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

type AuthorizeGetInput struct {
	ClientId            string `query:"client_id"`
	RedirectUri         string `query:"redirect_uri"`
	ResponseType        string `query:"response_type" validate:"required"`
	Scope               string `query:"scope"`
	State               string `query:"state"`
	Nonce               string `query:"nonce"`
	CodeChallenge       string `query:"code_challenge"`
	CodeChallengeMethod string `query:"code_challenge_method"`
}

// handleAuthorizeGet is step 1 of the OIDC flow.
// Headscale redirects the user here. We validate the request,
// then show the interstitial page asking for their AT Protocol handle.
func (s *Server) handleAuthorizeGet(e echo.Context) error {
	var input AuthorizeGetInput
	if err := e.Bind(&input); err != nil {
		return s.renderError(e, "Invalid Request", "Failed to parse the authorization request.")
	}

	if input.ResponseType != "code" {
		return s.renderError(e, "Unsupported Response Type", "Only 'code' response type is supported.")
	}

	if input.ClientId == "" {
		return s.renderError(e, "Missing Client ID", "The client_id parameter is required.")
	}

	if input.RedirectUri == "" {
		return s.renderError(e, "Missing Redirect URI", "The redirect_uri parameter is required.")
	}

	// Validate the client is registered
	client := s.findClient(input.ClientId)
	if client == nil {
		return s.renderError(e, "Unknown Client", fmt.Sprintf("Client '%s' is not registered.", input.ClientId))
	}

	// Validate redirect_uri is registered for this client
	if len(client.RedirectURIs) > 0 {
		found := false
		for _, uri := range client.RedirectURIs {
			if uri == input.RedirectUri {
				found = true
				break
			}
		}
		if !found {
			return s.renderError(e, "Invalid Redirect URI", "The redirect_uri is not registered for this client.")
		}
	}

	// Store the authorize params in session so we can retrieve them after
	// the AT Protocol auth flow completes.
	sess, _ := session.Get("atmesh", e)
	sess.Values["client_id"] = input.ClientId
	sess.Values["redirect_uri"] = input.RedirectUri
	sess.Values["scope"] = input.Scope
	sess.Values["state"] = input.State
	sess.Values["nonce"] = input.Nonce
	sess.Values["code_challenge"] = input.CodeChallenge
	sess.Values["code_challenge_method"] = input.CodeChallengeMethod
	sess.Save(e.Request(), e.Response())

	// Show the interstitial page
	return e.HTML(http.StatusOK, strings.ReplaceAll(authorizePageHTML, "__CLIENT_ID__", input.ClientId))
}

// handleAuthorizePost handles the AT Protocol handle submission.
// Phase 1: auto-approve (ignores handle, issues code immediately).
// Phase 2: resolve handle → DID → PDS, redirect to PDS for auth.
func (s *Server) handleAuthorizePost(e echo.Context) error {
	// Phase 1: if phase1=true in the form, auto-approve
	if e.FormValue("phase1") == "true" {
		return s.autoApproveFromSession(e)
	}

	handle := e.FormValue("handle")
	if handle == "" {
		return s.renderError(e, "Missing Handle", "An AT Protocol handle is required.")
	}

	// Get the OIDC params from the session (stored by handleAuthorizeGet)
	sess, _ := session.Get("atmesh", e)
	oidcClientId, _ := sess.Values["client_id"].(string)
	oidcRedirectUri, _ := sess.Values["redirect_uri"].(string)
	oidcScope, _ := sess.Values["scope"].(string)
	oidcState, _ := sess.Values["state"].(string)
	oidcNonce, _ := sess.Values["nonce"].(string)
	oidcCodeChallenge, _ := sess.Values["code_challenge"].(string)
	oidcCodeChallengeMethod, _ := sess.Values["code_challenge_method"].(string)

	if oidcClientId == "" || oidcRedirectUri == "" {
		return s.renderError(e, "Session Expired", "Please restart the authorization flow.")
	}

	// Start the AT Protocol OAuth flow via indigo.
	// StartAuthFlow resolves handle → DID → PDS → auth server metadata → PAR.
	// The CapturingStore wrapper captures the OAuth state that indigo generates.
	ctx := e.Request().Context()
	redirectURL, err := s.oauthApp.StartAuthFlow(ctx, handle)
	if err != nil {
		s.logger.Error("error starting AT Protocol OAuth flow", "handle", handle, "err", err)
		return s.renderError(e, "Authentication Failed", fmt.Sprintf("Could not start AT Protocol authentication: %v", err))
	}

	// Get the OAuth state that indigo generated and saved via the CapturingStore
	oauthState := s.capturingStore.GetLastState()
	if oauthState == "" {
		s.logger.Error("could not capture OAuth state from StartAuthFlow")
		return s.renderError(e, "Server Error", "Failed to initialize authentication flow.")
	}

	// Store the OIDC params in the OidcBridge table, keyed by the OAuth state.
	// When the PDS redirects back to /oauth/callback, we'll look up the OIDC
	// params using this state — no dependency on session cookies surviving
	// the cross-site redirect.
	bridge := &db.OidcBridge{
		OAuthState:              oauthState,
		OidcClientId:            oidcClientId,
		OidcRedirectUri:         oidcRedirectUri,
		OidcScope:               oidcScope,
		OidcState:               oidcState,
		OidcNonce:               oidcNonce,
		OidcCodeChallenge:       oidcCodeChallenge,
		OidcCodeChallengeMethod: oidcCodeChallengeMethod,
		Handle:                  handle,
	}
	if err := s.oauthStore.SaveOidcBridge(bridge); err != nil {
		s.logger.Error("error saving OIDC bridge", "err", err)
		return s.renderError(e, "Server Error", "Failed to save authorization state.")
	}

	// Redirect the user to the PDS authorization page
	return e.Redirect(http.StatusSeeOther, redirectURL)
}

// autoApproveFromSession reads the authorize params from the session
// and issues an auth code (Phase 1 auto-approve flow).
func (s *Server) autoApproveFromSession(e echo.Context) error {
	sess, _ := session.Get("atmesh", e)

	clientId, _ := sess.Values["client_id"].(string)
	redirectUri, _ := sess.Values["redirect_uri"].(string)
	scope, _ := sess.Values["scope"].(string)
	state, _ := sess.Values["state"].(string)
	nonce, _ := sess.Values["nonce"].(string)
	codeChallenge, _ := sess.Values["code_challenge"].(string)
	codeChallengeMethod, _ := sess.Values["code_challenge_method"].(string)

	if clientId == "" || redirectUri == "" {
		return s.renderError(e, "Session Expired", "Please restart the authorization flow.")
	}

	sub := "did:plc:placeholder"
	preferredUsername := "placeholder"
	email := s.config.AdminEmail

	code := oidc.GenerateAuthCode()

	authReq := &db.OidcAuthCode{
		Code:                code,
		ClientId:            clientId,
		RedirectUri:         redirectUri,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Sub:                 sub,
		PreferredUsername:   preferredUsername,
		Email:               email,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := s.db.DB.Create(authReq).Error; err != nil {
		s.logger.Error("error creating auth request", "err", err)
		return s.renderError(e, "Server Error", "Could not create the authorization request.")
	}

	redirectUrl := fmt.Sprintf("%s?code=%s", redirectUri, code)
	if state != "" {
		redirectUrl += fmt.Sprintf("&state=%s", state)
	}

	// Show the success page with a redirect
	html := strings.ReplaceAll(successPageHTML, "{{.ClientID}}", clientId)
	html = strings.ReplaceAll(html, "{{.RedirectURL}}", redirectUrl)
	return e.HTML(http.StatusOK, html)
}

// autoApprove is the direct auto-approve (no session, used by tests).
func (s *Server) autoApprove(e echo.Context, input *AuthorizeGetInput) error {
	sub := "did:plc:placeholder"
	preferredUsername := "placeholder"
	email := s.config.AdminEmail

	code := oidc.GenerateAuthCode()

	authReq := &db.OidcAuthCode{
		Code:                code,
		ClientId:            input.ClientId,
		RedirectUri:         input.RedirectUri,
		Scope:               input.Scope,
		State:               input.State,
		Nonce:               input.Nonce,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		Sub:                 sub,
		PreferredUsername:   preferredUsername,
		Email:               email,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := s.db.DB.Create(authReq).Error; err != nil {
		s.logger.Error("error creating auth request", "err", err)
		return e.JSON(http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}

	redirectUrl := fmt.Sprintf("%s?code=%s", input.RedirectUri, code)
	if input.State != "" {
		redirectUrl += fmt.Sprintf("&state=%s", input.State)
	}

	return e.Redirect(http.StatusSeeOther, redirectUrl)
}

// renderError renders the error page.
func (s *Server) renderError(e echo.Context, error string, description string) error {
	html := strings.ReplaceAll(errorPageHTML, "{{.Error}}", error)
	html = strings.ReplaceAll(html, "{{.Description}}", description)
	return e.HTML(http.StatusBadRequest, html)
}
