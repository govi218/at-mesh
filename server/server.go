package server

import (
	"context"
	"crypto/ecdsa"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/go-playground/validator"
	"github.com/gorilla/sessions"
	"github.com/govi218/at-mesh/headscale"
	"github.com/govi218/at-mesh/internal/db"
	"github.com/govi218/at-mesh/oidc"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
	slogecho "github.com/samber/slog-echo"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

//go:embed all:web
var webFS embed.FS

type Args struct {
	Addr          string
	Hostname      string
	JwkPath       string
	DbName        string
	HeadscaleUrl  string
	HeadscaleKey  string
	AdminEmail    string
	AdminToken    string
	SessionSecret string
	Version       string
	LogLevel      string
	Clients       []OAuthClient
}

type Server struct {
	echo           *echo.Echo
	db             *db.DB
	oauthStore     *db.OAuthStore
	capturingStore *db.CapturingStore
	logger         *slog.Logger
	config         *config
	privateKey     *ecdsa.PrivateKey
	jwkKey         jwk.Key
	oidcProvider   *oidc.Provider
	headscale      *headscale.Client
	oauthApp       *oauth.ClientApp
	sessionStore   sessions.Store
	validator      *validator.Validate
}

type OAuthClient struct {
	ID           string
	Secret       string
	RedirectURIs []string
}

type config struct {
	Addr          string
	Hostname      string
	HeadscaleUrl  string
	HeadscaleKey  string
	AdminEmail    string
	AdminToken    string
	Version       string
	SessionSecret string
	Clients       []OAuthClient
}

func New(args *Args) (*Server, error) {
	if args.Hostname == "" {
		return nil, fmt.Errorf("ATMESH_HOSTNAME is required")
	}
	if args.JwkPath == "" {
		return nil, fmt.Errorf("ATMESH_JWK_PATH is required")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(args.LogLevel),
	}))

	// Load JWK
	keyData, err := os.ReadFile(args.JwkPath)
	if err != nil {
		return nil, fmt.Errorf("error reading JWK file: %w", err)
	}

	keySet, err := jwk.ParseKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("error parsing JWK: %w", err)
	}

	var privateKey ecdsa.PrivateKey
	if err := keySet.Raw(&privateKey); err != nil {
		return nil, fmt.Errorf("error extracting private key: %w", err)
	}

	// Init DB
	gormDb, err := gorm.Open(sqlite.Open(args.DbName), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("error opening database: %w", err)
	}

	if err := gormDb.AutoMigrate(&db.OidcAuthCode{}); err != nil {
		return nil, fmt.Errorf("error migrating database: %w", err)
	}

	// Init OAuth store for indigo AT Protocol OAuth client
	oauthStore := db.NewOAuthStore(gormDb)
	if err := oauthStore.AutoMigrate(); err != nil {
		return nil, fmt.Errorf("error migrating OAuth database: %w", err)
	}

	database := &db.DB{DB: gormDb}

	// Init indigo OAuth client app (public client)
	// Wrap the store in a CapturingStore so we can retrieve the OAuth state
	// that indigo generates inside StartAuthFlow.
	// Use the hostname for the callback URL so it works from any device.
	callbackURL := fmt.Sprintf("https://%s/oauth/callback", args.Hostname)
	clientID := fmt.Sprintf("https://%s/oauth/client-metadata.json", args.Hostname)
	oauthConfig := oauth.NewPublicConfig(clientID, callbackURL, []string{"atproto"})
	capturingStore := db.NewCapturingStore(oauthStore)
	oauthApp := oauth.NewClientApp(&oauthConfig, capturingStore)

	cfg := &config{
		Addr:          args.Addr,
		Hostname:      args.Hostname,
		HeadscaleUrl:  args.HeadscaleUrl,
		HeadscaleKey:  args.HeadscaleKey,
		AdminEmail:    args.AdminEmail,
		AdminToken:    args.AdminToken,
		Version:       args.Version,
		SessionSecret: args.SessionSecret,
		Clients:       args.Clients,
	}

	// Init OIDC provider
	oidcProvider := oidc.NewProvider(&oidc.ProviderArgs{
		Hostname:   args.Hostname,
		PrivateKey: &privateKey,
		JwkKey:     keySet,
	})

	// Init Headscale client
	var hsClient *headscale.Client
	if args.HeadscaleUrl != "" {
		hsClient = headscale.NewClient(args.HeadscaleUrl, args.HeadscaleKey)
	}

	// Session store
	cookieStore := sessions.NewCookieStore([]byte(args.SessionSecret))
	cookieStore.Options.Secure = true
	cookieStore.Options.SameSite = http.SameSiteLaxMode
	cookieStore.Options.HttpOnly = true
	cookieStore.Options.Path = "/"

	s := &Server{
		db:             database,
		oauthStore:     oauthStore,
		capturingStore: capturingStore,
		logger:         logger,
		config:         cfg,
		privateKey:     &privateKey,
		jwkKey:         keySet,
		oidcProvider:   oidcProvider,
		headscale:      hsClient,
		oauthApp:       oauthApp,
		sessionStore:   cookieStore,
		validator:      validator.New(),
	}

	s.setupEcho()
	return s, nil
}

func (s *Server) setupEcho() {
	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.RequestID())
	e.Use(slogecho.New(s.logger))
	e.Use(middleware.Recover())
	e.Use(session.Middleware(s.sessionStore.(*sessions.CookieStore)))

	// OIDC discovery
	e.GET("/.well-known/openid-configuration", s.handleOidcDiscovery)
	e.GET("/.well-known/jwks.json", s.handleOidcJwks)
	e.GET("/.well-known/webfinger", s.handleWebFinger)

	// OIDC flow
	e.GET("/authorize", s.handleAuthorizeGet)
	e.POST("/authorize", s.handleAuthorizePost)
	e.POST("/token", s.handleToken)
	e.GET("/userinfo", s.handleUserinfo)

	// AT Protocol OAuth client callback (PDS redirects here after user auth)
	e.GET("/oauth/callback", s.handleATProtoCallback)
	// Client metadata endpoint (for non-localhost OAuth clients)
	e.GET("/oauth/client-metadata.json", s.handleClientMetadata)

	// Admin UI
	e.GET("/admin/login", s.handleAdminLoginGet)
	e.POST("/admin/login", s.handleAdminLoginPost)
	e.POST("/admin/logout", s.handleAdminLogout)

	// Whitelist API (admin-only)
	whitelistGroup := e.Group("/api/v1/whitelist", s.adminMiddleware)
	whitelistGroup.GET("", s.handleListWhitelist)
	whitelistGroup.POST("", s.handleAddWhitelist)
	whitelistGroup.DELETE("/:id", s.handleDeleteWhitelist)

	// Headscale API proxy (admin-only, excludes /api/v1/whitelist)
	if s.config.HeadscaleUrl != "" {
		e.Any("/api/v1/*", s.newHeadscaleProxy(), s.adminMiddleware)
	}

	// Static files (headscale-ui build)
	staticFS, _ := fs.Sub(webFS, "web")
	e.GET("/web/*", echo.StaticDirectoryHandler(staticFS, false))

	// Health
	e.GET("/health", s.handleHealth)

	s.echo = e
}

func (s *Server) Serve(ctx context.Context) error {
	s.logger.Info("starting at-mesh", "hostname", s.config.Hostname, "addr", s.config.Addr, "version", s.config.Version)

	server := &http.Server{
		Addr:    s.config.Addr,
		Handler: s.echo,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// findClient looks up a registered OAuth client by ID.
func (s *Server) findClient(clientID string) *OAuthClient {
	for i := range s.config.Clients {
		if s.config.Clients[i].ID == clientID {
			return &s.config.Clients[i]
		}
	}
	return nil
}

// validateClient validates a client_id/client_secret pair and checks
// that the redirect_uri is registered for that client.
func (s *Server) validateClient(clientID, clientSecret, redirectURI string) *OAuthClient {
	client := s.findClient(clientID)
	if client == nil {
		return nil
	}
	if client.Secret != "" && client.Secret != clientSecret {
		return nil
	}
	if len(client.RedirectURIs) > 0 && redirectURI != "" {
		found := false
		for _, uri := range client.RedirectURIs {
			if uri == redirectURI {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return client
}
