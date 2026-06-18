package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/govi218/at-mesh/internal/db"
	"github.com/govi218/at-mesh/oidc"
	"github.com/labstack/echo/v4"
)

type AuthorizeGetInput struct {
	ClientId     string `query:"client_id"`
	RedirectUri string `query:"redirect_uri"`
	ResponseType string `query:"response_type" validate:"required"`
	Scope        string `query:"scope"`
	State        string `query:"state"`
	Nonce        string `query:"nonce"`
	CodeChallenge       string `query:"code_challenge"`
	CodeChallengeMethod string `query:"code_challenge_method"`
}

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

	// Phase 1: auto-approve. Generate a stub user and issue code.
	// Phase 2 will replace this with AT Protocol OAuth flow.
	// Phase 3 will add membership check here.
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
		PreferredUsername:    preferredUsername,
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

func (s *Server) handleAuthorizePost(e echo.Context) error {
	// Phase 2: this will handle the AT Protocol auth callback
	return e.JSON(http.StatusNotImplemented, map[string]string{"error": "not_implemented"})
}
