package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func (s *Server) handleOidcDiscovery(e echo.Context) error {
	return e.JSON(http.StatusOK, s.oidcProvider.Discovery())
}
