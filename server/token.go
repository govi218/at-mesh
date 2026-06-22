package server

import (
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
	var authReq db.OidcAuthCode
	if err := s.db.DB.Where("code = ?", req.Code).First(&authReq).Error; err != nil {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "code not found"})
	}

	// One-time use: reject if code has already been exchanged
	if authReq.AccessToken != "" {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "code already used"})
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

	// TODO: PKCE validation

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

	// Generate an opaque access token and store it on the auth request
	// so /userinfo can look up the claims by access token.
	accessToken := oidc.GenerateAuthCode()
	// Clear the code (one-time use) but keep the row for userinfo lookups.
	if err := s.db.DB.Model(&authReq).Updates(map[string]interface{}{
		"access_token": accessToken,
		"code":         "",
	}).Error; err != nil {
		s.logger.Error("error storing access token", "err", err)
		return e.JSON(http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}

	return e.JSON(http.StatusOK, map[string]string{
		"access_token": accessToken,
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

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")

	// Look up the auth request by access token
	var authReq db.OidcAuthCode
	if err := s.db.DB.Where("access_token = ?", accessToken).First(&authReq).Error; err != nil {
		return e.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	}

	return e.JSON(http.StatusOK, map[string]string{
		"sub":                authReq.Sub,
		"name":               authReq.PreferredUsername,
		"preferred_username": authReq.PreferredUsername,
	})
}
