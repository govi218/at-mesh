package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/govi218/at-mesh/internal/db"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

// adminMiddleware checks if the user is authenticated as admin.
// Returns 401 JSON for API requests, redirects to /admin/login for pages.
func (s *Server) adminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(e echo.Context) error {
		sess, _ := session.Get("atmesh", e)
		if auth, ok := sess.Values["admin"].(bool); !ok || !auth {
			// API requests get JSON 401, page requests get redirected
			if e.Path() != "/admin/login" && (e.Request().Header.Get("Accept") == "application/json" ||
				e.Request().Header.Get("Content-Type") == "application/json" ||
				strings.HasPrefix(e.Path(), "/api/")) {
				return e.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			}
			return e.Redirect(http.StatusSeeOther, "/admin/login")
		}
		return next(e)
	}
}

// handleAdminLoginGet shows the admin login form.
func (s *Server) handleAdminLoginGet(e echo.Context) error {
	return e.HTML(http.StatusOK, adminLoginHTML)
}

// handleAdminLoginPost validates the admin token and sets the session.
func (s *Server) handleAdminLoginPost(e echo.Context) error {
	token := e.FormValue("token")
	if token == "" || token != s.config.AdminToken {
		return e.HTML(http.StatusUnauthorized, strings.ReplaceAll(adminLoginHTML, "__ERROR__", "Invalid token"))
	}

	sess, _ := session.Get("atmesh", e)
	sess.Values["admin"] = true
	sess.Save(e.Request(), e.Response())

	return e.Redirect(http.StatusSeeOther, "/web/")
}

// handleAdminLogout clears the admin session.
func (s *Server) handleAdminLogout(e echo.Context) error {
	sess, _ := session.Get("atmesh", e)
	delete(sess.Values, "admin")
	sess.Save(e.Request(), e.Response())
	return e.Redirect(http.StatusSeeOther, "/admin/login")
}

// handleListWhitelist returns all whitelist entries as JSON.
func (s *Server) handleListWhitelist(e echo.Context) error {
	var entries []db.WhitelistEntry
	if err := s.db.DB.Order("created_at DESC").Find(&entries).Error; err != nil {
		return e.JSON(http.StatusInternalServerError, map[string]string{"error": "database error"})
	}
	return e.JSON(http.StatusOK, entries)
}

// handleAddWhitelist adds a new whitelist entry.
func (s *Server) handleAddWhitelist(e echo.Context) error {
	var input struct {
		DID      string `json:"did"`
		Handle   string `json:"handle"`
		MaxNodes int    `json:"max_nodes"`
		Notes    string `json:"notes"`
	}
	if err := e.Bind(&input); err != nil {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}
	if input.DID == "" {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "did is required"})
	}

	entry := db.WhitelistEntry{
		DID:      input.DID,
		Handle:   input.Handle,
		MaxNodes: input.MaxNodes,
		Notes:    input.Notes,
	}
	if err := s.db.DB.Create(&entry).Error; err != nil {
		return e.JSON(http.StatusConflict, map[string]string{"error": "DID already exists"})
	}
	return e.JSON(http.StatusCreated, entry)
}

// handleDeleteWhitelist removes a whitelist entry by ID.
func (s *Server) handleDeleteWhitelist(e echo.Context) error {
	id := e.Param("id")
	if id == "" {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "id is required"})
	}
	idUint, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return e.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	if err := s.db.DB.Delete(&db.WhitelistEntry{}, idUint).Error; err != nil {
		return e.JSON(http.StatusInternalServerError, map[string]string{"error": "database error"})
	}
	return e.JSON(http.StatusOK, map[string]string{"status": "deleted"})
}

const adminLoginHTML = `<!DOCTYPE html>
<html>
<head>
	<title>at-mesh Admin</title>
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<style>
		body { font-family: system-ui, sans-serif; background: #1a1a2e; color: #eee; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
		.card { background: #16213e; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); width: 360px; }
		h1 { margin: 0 0 1.5rem; font-size: 1.25rem; text-align: center; }
		input { width: 100%; padding: 0.75rem; margin-bottom: 1rem; border: 1px solid #333; border-radius: 4px; background: #0f3460; color: #eee; font-size: 1rem; box-sizing: border-box; }
		input:focus { outline: none; border-color: #e94560; }
		button { width: 100%; padding: 0.75rem; border: none; border-radius: 4px; background: #e94560; color: #fff; font-size: 1rem; cursor: pointer; }
		button:hover { background: #c73e54; }
		.error { color: #e94560; margin-bottom: 1rem; font-size: 0.875rem; text-align: center; }
	</style>
</head>
<body>
	<div class="card">
		<h1>at-mesh Admin</h1>
		__ERROR__
		<form method="POST" action="/admin/login">
			<input type="password" name="token" placeholder="Admin token" autofocus required>
			<button type="submit">Login</button>
		</form>
	</div>
</body>
</html>`
