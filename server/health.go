package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func (s *Server) handleHealth(e echo.Context) error {
	return e.JSON(http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.config.Version,
	})
}
