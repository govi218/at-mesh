package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func (s *Server) handleOidcJwks(e echo.Context) error {
	jwks, err := s.oidcProvider.JWKS()
	if err != nil {
		s.logger.Error("error generating JWKS", "err", err)
		return e.JSON(http.StatusInternalServerError, map[string]string{"error": "internal_error"})
	}
	return e.JSON(http.StatusOK, jwks)
}
