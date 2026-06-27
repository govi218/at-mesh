package server

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/labstack/echo/v4"
)

// newHeadscaleProxy creates a reverse proxy to Headscale with API key injection.
func (s *Server) newHeadscaleProxy() echo.HandlerFunc {
	target, err := url.Parse(s.config.HeadscaleUrl)
	if err != nil {
		s.logger.Error("invalid headscale URL for proxy", "url", s.config.HeadscaleUrl, "err", err)
		return func(e echo.Context) error {
			return e.JSON(http.StatusBadGateway, map[string]string{"error": "headscale URL not configured"})
		}
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("Authorization", "Bearer "+s.config.HeadscaleKey)
		req.Header.Set("Accept", "application/json")
	}

	return func(e echo.Context) error {
		// Strip the /api/v1 prefix since Headscale expects it
		// (ReverseProxy already prepends the target path, so we keep it)
		proxy.ServeHTTP(e.Response(), e.Request())
		return nil
	}
}
