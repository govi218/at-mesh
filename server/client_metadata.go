package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// handleClientMetadata serves the OAuth client metadata document.
// For non-localhost clients, the client_id URL must serve this document.
func (s *Server) handleClientMetadata(e echo.Context) error {
	meta := s.oauthApp.Config.ClientMetadata()
	name := "at-mesh"
	meta.ClientName = &name
	return e.JSON(http.StatusOK, meta)
}
