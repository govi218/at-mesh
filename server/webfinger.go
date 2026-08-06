package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/govi218/at-mesh/internal/db"
	"github.com/labstack/echo/v4"
)

type WebFingerResponse struct {
	Subject string              `json:"subject"`
	Links   []WebFingerLink     `json:"links"`
}

type WebFingerLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

func (s *Server) handleWebFinger(e echo.Context) error {
	resource := e.QueryParam("resource")
	if resource == "" {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "missing resource parameter"})
	}

	// Expected: acct:<anything>@<hostname>
	if !strings.HasPrefix(resource, "acct:") {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "resource must be an acct: URI"})
	}

	addr := strings.TrimPrefix(resource, "acct:")
	at := strings.LastIndex(addr, "@")
	if at == -1 {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid acct: URI"})
	}

	domain := addr[at+1:]
	if domain != s.config.Hostname {
		return e.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
	}

	// If the whitelist is non-empty, only respond to queries for known handles.
	// Empty whitelist = bootstrap mode (respond to all).
	handle := addr[:at]
	var count int64
	s.db.DB.Model(&db.WhitelistEntry{}).Count(&count)
	if count > 0 {
		email := handle + "@" + s.config.Hostname
		var entry db.WhitelistEntry
		if err := s.db.DB.Where("handle = ? OR email = ?", handle, email).First(&entry).Error; err != nil {
			return e.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
		}
	}

	issuer := fmt.Sprintf("https://%s", s.config.Hostname)
	return e.JSON(http.StatusOK, WebFingerResponse{
		Subject: resource,
		Links: []WebFingerLink{
			{
				Rel:  "http://openid.net/specs/connect/1.0/issuer",
				Href: issuer,
			},
		},
	})
}
