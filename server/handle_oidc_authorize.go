package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/govi218/at-mesh/atproto"
	"github.com/govi218/at-mesh/internal/db"
	"github.com/govi218/at-mesh/oidc"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo-contrib/session"
)

type AuthorizeGetInput struct {
	ClientId            string `query:"client_id"`
	RedirectUri        string `query:"redirect_uri"`
	ResponseType        string `query:"response_type" validate:"required"`
	Scope               string `query:"scope"`
	State               string `query:"state"`
	Nonce               string `query:"nonce"`
	CodeChallenge       string `query:"code_challenge"`
	CodeChallengeMethod string `query:"code_challenge_method"`
}

// handleAuthorizeGet is step 1 of the OIDC flow.
// Headscale redirects the user here. We validate the request,
// then show an interstitial page asking for their AT Protocol handle.
func (s *Server) handleAuthorizeGet(e echo.Context) error {
	var input AuthorizeGetInput
	if err := e.Bind(&input); err != nil {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "failed to bind request"})
	}

	if input.ResponseType != "code" {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported_response_type"})
	}

	if input.ClientId == "" {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "client_id is required"})
	}

	if input.RedirectUri == "" {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri is required"})
	}

	// Validate the client is registered
	client := s.findClient(input.ClientId)
	if client == nil {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_client", "error_description": "unknown client_id"})
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
			return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri not registered for this client"})
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

	// Phase 1: auto-approve. Skip the interstitial page and issue code directly.
	// Phase 2 will show the "enter your AT handle" page instead.
	return s.autoApprove(e, &input)
}

// handleAuthorizePost handles the AT Protocol handle submission.
// Phase 2: resolve handle → DID → PDS, redirect to PDS for auth.
func (s *Server) handleAuthorizePost(e echo.Context) error {
	handle := e.FormValue("handle")
	if handle == "" {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "handle is required"})
	}

	// Resolve handle → DID
	did, err := atproto.ResolveHandle(handle)
	if err != nil {
		s.logger.Error("error resolving handle", "handle", handle, "err", err)
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "could not resolve handle"})
	}

	// Resolve DID → PDS endpoint
	pdsUrl, err := atproto.ResolvePDSEndpoint(did)
	if err != nil {
		s.logger.Error("error resolving PDS", "did", did, "err", err)
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "could not resolve PDS"})
	}

	// Phase 2: redirect to PDS for AT Protocol OAuth
	// For now, log and return not implemented
	s.logger.Info("resolved handle to PDS", "handle", handle, "did", did, "pds", pdsUrl)
	return e.JSON(http.StatusNotImplemented, map[string]string{"error": "not_implemented", "error_description": "AT Protocol OAuth not yet implemented"})
}

// handleAuthorizeCallback handles the callback from the PDS after
// AT Protocol OAuth completes. Phase 2 will fill this in.
func (s *Server) handleAuthorizeCallback(e echo.Context) error {
	// Phase 2: PDS calls back here with an authorization code or token.
	// We'll exchange it for the user's DID, check the member list,
	// and issue the OIDC authorization code.

	return e.JSON(http.StatusNotImplemented, map[string]string{"error": "not_implemented", "error_description": "AT Protocol OAuth callback not yet implemented"})
}

// autoApprove is the Phase 1 stub: skip AT Protocol auth, issue code immediately.
func (s *Server) autoApprove(e echo.Context, input *AuthorizeGetInput) error {
	sub := "did:plc:placeholder"
	preferredUsername := "placeholder"
	email := s.config.AdminEmail

	code := oidc.GenerateAuthCode()

	authReq := &db.AuthRequest{
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
