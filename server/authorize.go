package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/govi218/at-mesh/internal/db"
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
// The OIDC client redirects the user here. We validate the request,
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
// It resolves the handle → DID → PDS, then redirects to the PDS for auth.
func (s *Server) handleAuthorizePost(e echo.Context) error {
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

// renderError renders the error page.
func (s *Server) renderError(e echo.Context, error string, description string) error {
	html := strings.ReplaceAll(errorPageHTML, "{{.Error}}", error)
	html = strings.ReplaceAll(html, "{{.Description}}", description)
	return e.HTML(http.StatusBadRequest, html)
}
