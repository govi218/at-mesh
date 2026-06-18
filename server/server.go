package server

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-playground/validator"
	"github.com/gorilla/sessions"
	"github.com/govi218/at-mesh/headscale"
	"github.com/govi218/at-mesh/internal/db"
	"github.com/govi218/at-mesh/oidc"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	slogecho "github.com/samber/slog-echo"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Args struct {
	Addr          string
	Hostname      string
	JwkPath       string
	DbName        string
	HeadscaleUrl  string
	HeadscaleKey  string
	AdminEmail    string
	SessionSecret string
	Version       string
	LogLevel      string
}

type Server struct {
	echo          *echo.Echo
	db            *db.DB
	logger        *slog.Logger
	config        *config
	privateKey    *ecdsa.PrivateKey
	jwkKey        jwk.Key
	oidcProvider  *oidc.Provider
	headscale     *headscale.Client
	sessionStore  sessions.Store
	validator     *validator.Validate
}

type config struct {
	Addr          string
	Hostname      string
	HeadscaleUrl  string
	HeadscaleKey  string
	AdminEmail    string
	Version       string
	SessionSecret string
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

	if err := gormDb.AutoMigrate(&db.AuthRequest{}); err != nil {
		return nil, fmt.Errorf("error migrating database: %w", err)
	}

	database := &db.DB{DB: gormDb}

	cfg := &config{
		Addr:          args.Addr,
		Hostname:      args.Hostname,
		HeadscaleUrl:  args.HeadscaleUrl,
		HeadscaleKey:  args.HeadscaleKey,
		AdminEmail:    args.AdminEmail,
		Version:       args.Version,
		SessionSecret: args.SessionSecret,
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

	s := &Server{
		db:           database,
		logger:       logger,
		config:       cfg,
		privateKey:   &privateKey,
		jwkKey:       keySet,
		oidcProvider: oidcProvider,
		headscale:    hsClient,
		sessionStore: cookieStore,
		validator:    validator.New(),
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
