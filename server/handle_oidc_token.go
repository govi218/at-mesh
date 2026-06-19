package server

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/govi218/at-mesh/internal/db"
	"github.com/govi218/at-mesh/oidc"
	"github.com/labstack/echo/v4"
)

type TokenRequest struct {
	GrantType    string `form:"grant_type"`
	Code         string `form:"code"`
	RedirectUri  string `form:"redirect_uri"`
	ClientId     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	CodeVerifier string `form:"code_verifier"`
}

func (s *Server) handleToken(e echo.Context) error {
	var req TokenRequest
	if err := e.Bind(&req); err != nil {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request"})
	}

	if req.GrantType != "authorization_code" {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}

	if req.Code == "" {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "code is required"})
	}

	// Look up the auth request
	var authReq db.AuthRequest
	if err := s.db.DB.Where("code = ?", req.Code).First(&authReq).Error; err != nil {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "code not found"})
	}

	// Validate code hasn't expired
	if time.Now().After(authReq.ExpiresAt) {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "code expired"})
	}

	// Validate client_id matches
	if req.ClientId != "" && req.ClientId != authReq.ClientId {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "client_id mismatch"})
	}

	// Validate client_secret if clients are registered
	if req.ClientId != "" {
		client := s.validateClient(req.ClientId, req.ClientSecret, "")
		if client == nil {
			return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_client", "error_description": "invalid client credentials"})
		}
	}

	// Validate redirect_uri matches
	if req.RedirectUri != "" && req.RedirectUri != authReq.RedirectUri {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
	}

	// PKCE validation (Phase 1: skip if no challenge was stored)
	// Phase 2 will enforce PKCE

	log.Print("authhzzz", authReq)

	// Issue id_token
	idToken, err := s.oidcProvider.IssueIDToken(
		authReq.Sub,
		authReq.PreferredUsername,
		authReq.Email,
		authReq.ClientId,
	)
	if err != nil {
		s.logger.Error("error issuing id_token", "err", err)
		return e.JSON(http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}

	// Delete the used auth request (one-time use)
	s.db.DB.Where("code = ?", req.Code).Delete(&db.AuthRequest{})

	return e.JSON(http.StatusOK, map[string]string{
		"access_token": oidc.GenerateAuthCode(), // opaque token, not used for resource access
		"token_type":   "Bearer",
		"expires_in":   "3600",
		"id_token":     idToken,
	})
}

func (s *Server) handleUserinfo(e echo.Context) error {
	authHeader := e.Request().Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return e.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}

	// Phase 1: return placeholder claims
	// Phase 2: parse the access token and return real claims
	_ = authHeader

	return e.JSON(http.StatusOK, map[string]string{
		"sub":                "did:plc:placeholder",
		"name":               "placeholder",
		"preferred_username": "placeholder",
	})
}
