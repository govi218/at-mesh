package server

import (
	"fmt"
	"net/http"

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

	// Expected: acct:admin@mesh.glados.computer
	expectedResource := fmt.Sprintf("acct:%s", s.config.AdminEmail)
	if resource != expectedResource {
		return e.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
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
