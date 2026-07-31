package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/govi218/at-mesh/internal/db"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestServer(t *testing.T) *Server {
	t.Helper()

	// Generate an ephemeral JWK so tests don't depend on keys/ existing
	jwkPath := filepath.Join(t.TempDir(), "jwk.key")
	if err := CreateJwk(jwkPath); err != nil {
		t.Fatalf("create jwk: %v", err)
	}

	gormDb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormDb.AutoMigrate(&db.OidcAuthCode{}, &db.WhitelistEntry{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	args := &Args{
		Addr:          "127.0.0.1:0",
		Hostname:      "mesh.glados.computer",
		JwkPath:       jwkPath,
		DbName:        ":memory:",
		AdminEmail:    "admin@mesh.glados.computer",
		AdminToken:    "test-admin-token",
		SessionSecret: "test-secret",
		Clients: []OAuthClient{
			{
				ID:           "headscale",
				Secret:       "secret123",
				RedirectURIs: []string{"http://localhost:9999/callback"},
			},
		},
	}

	s, err := New(args)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	s.db = &db.DB{DB: gormDb}

	return s
}

func startTestServer(t *testing.T, s *Server) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		srv := &http.Server{Handler: s.echo}
		_ = srv.Serve(listener)
	}()

	t.Cleanup(func() { listener.Close() })

	return "http://" + listener.Addr().String()
}

// makeClient creates an HTTP client that doesn't follow redirects
// but does store cookies (needed for sessions).
func makeClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestDiscovery(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	resp, err := http.Get(base + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if doc["issuer"] != "https://mesh.glados.computer" {
		t.Errorf("issuer = %v, want https://mesh.glados.computer", doc["issuer"])
	}
	if doc["authorization_endpoint"] != "https://mesh.glados.computer/authorize" {
		t.Errorf("authorize = %v", doc["authorization_endpoint"])
	}
	if doc["token_endpoint"] != "https://mesh.glados.computer/token" {
		t.Errorf("token = %v", doc["token_endpoint"])
	}
}

func TestJWKS(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	resp, err := http.Get(base + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Alg string `json:"alg"`
			Kty string `json:"kty"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(jwks.Keys))
	}
	if jwks.Keys[0].Alg != "ES256" {
		t.Errorf("alg = %v, want ES256", jwks.Keys[0].Alg)
	}
	if jwks.Keys[0].Kid == "" {
		t.Error("kid is empty")
	}
}

func TestWebFinger(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	resp, err := http.Get(base + "/.well-known/webfinger?resource=acct:admin@mesh.glados.computer")
	if err != nil {
		t.Fatalf("get webfinger: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	var wf struct {
		Subject string `json:"subject"`
		Links   []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wf); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if wf.Subject != "acct:admin@mesh.glados.computer" {
		t.Errorf("subject = %v", wf.Subject)
	}
	if len(wf.Links) != 1 || wf.Links[0].Href != "https://mesh.glados.computer" {
		t.Errorf("links = %v", wf.Links)
	}
}

func TestAuthorizeShowsPage(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	client := makeClient()

	resp, err := client.Get(base + "/authorize?client_id=headscale&redirect_uri=http://localhost:9999/callback&response_type=code&scope=openid+profile+email&state=test123")
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if !strings.Contains(html, "at-mesh") {
		t.Error("page doesn't contain 'at-mesh'")
	}
	if !strings.Contains(html, "headscale") {
		t.Error("page doesn't show client_id")
	}
	if !strings.Contains(html, "phase1") {
		t.Error("page doesn't have phase1 form")
	}
}

func TestAuthorizeUnknownClient(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	resp, err := http.Get(base + "/authorize?client_id=evil&redirect_uri=http://localhost:9999/callback&response_type=code&scope=openid")
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Unknown Client") {
		t.Errorf("body doesn't show unknown client error, got: %s", body)
	}
}

func TestAuthorizeBadRedirectURI(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	resp, err := http.Get(base + "/authorize?client_id=headscale&redirect_uri=https://evil.com/steal&response_type=code&scope=openid")
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Invalid Redirect URI") {
		t.Errorf("body doesn't show redirect_uri error, got: %s", body)
	}
}

// fullAuthorizeFlow does the two-step Phase 1 flow:
// 1. GET /authorize → get session cookie + HTML page
// 2. POST /authorize with phase1=true → get success page with redirect URL
// Returns the redirect URL (containing the code).
func fullAuthorizeFlow(t *testing.T, base string) string {
	client := makeClient()

	// Step 1: GET /authorize — get the page + session cookie
	resp, err := client.Get(base + "/authorize?client_id=headscale&redirect_uri=http://localhost:9999/callback&response_type=code&scope=openid+profile+email&state=test")
	if err != nil {
		t.Fatalf("authorize GET: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("authorize GET status %d, want 200", resp.StatusCode)
	}

	// Step 2: POST /authorize with phase1=true — auto-approve
	resp, err = client.PostForm(base+"/authorize", url.Values{
		"phase1": {"true"},
	})
	if err != nil {
		t.Fatalf("authorize POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("authorize POST status %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	// The success page contains the redirect URL in the script tag
	// Extract it from: window.location.href = "..."
	idx := strings.Index(html, `window.location.href = "`)
	if idx == -1 {
		t.Fatalf("success page doesn't contain redirect URL: %s", html)
	}
	start := idx + len(`window.location.href = "`)
	end := strings.Index(html[start:], `"`)
	if end == -1 {
		t.Fatalf("can't find end of redirect URL: %s", html)
	}

	redirectURL := html[start : start+end]
	if !strings.Contains(redirectURL, "code=") {
		t.Fatalf("redirect URL doesn't contain code: %s", redirectURL)
	}

	return redirectURL
}

func TestPhase1AutoApprove(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	redirectURL := fullAuthorizeFlow(t, base)

	if !strings.Contains(redirectURL, "http://localhost:9999/callback?code=") {
		t.Errorf("redirect = %v, want callback with code", redirectURL)
	}
	if !strings.Contains(redirectURL, "state=test") {
		t.Errorf("state not preserved in %v", redirectURL)
	}
}

func TestTokenExchange(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	redirectURL := fullAuthorizeFlow(t, base)
	u, _ := url.Parse(redirectURL)
	code := u.Query().Get("code")

	tokenResp, err := http.PostForm(base+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"headscale"},
		"client_secret": {"secret123"},
		"redirect_uri":  {"http://localhost:9999/callback"},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("status %d: %s", tokenResp.StatusCode, body)
	}

	var token map[string]any
	json.NewDecoder(tokenResp.Body).Decode(&token)

	if _, ok := token["id_token"]; !ok {
		t.Error("no id_token in response")
	}
	if token["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", token["token_type"])
	}
}

func TestTokenWrongSecret(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	redirectURL := fullAuthorizeFlow(t, base)
	u, _ := url.Parse(redirectURL)
	code := u.Query().Get("code")

	tokenResp, err := http.PostForm(base+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"headscale"},
		"client_secret": {"wrong"},
		"redirect_uri":  {"http://localhost:9999/callback"},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 400 {
		t.Fatalf("status %d, want 400", tokenResp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(tokenResp.Body).Decode(&body)
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}
}

func TestTokenCodeReuse(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	redirectURL := fullAuthorizeFlow(t, base)
	u, _ := url.Parse(redirectURL)
	code := u.Query().Get("code")

	// First exchange — should succeed
	tokenResp, err := http.PostForm(base+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"headscale"},
		"client_secret": {"secret123"},
		"redirect_uri":  {"http://localhost:9999/callback"},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		t.Fatalf("first exchange: status %d", tokenResp.StatusCode)
	}

	// Second exchange — should fail
	reuseResp, err := http.PostForm(base+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"headscale"},
		"client_secret": {"secret123"},
		"redirect_uri":  {"http://localhost:9999/callback"},
	})
	if err != nil {
		t.Fatalf("token reuse: %v", err)
	}
	defer reuseResp.Body.Close()

	if reuseResp.StatusCode != 400 {
		t.Fatalf("reuse: status %d, want 400", reuseResp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(reuseResp.Body).Decode(&body)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

func TestUserinfo(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	// Do a full Phase 1 flow to get a real access token
	redirectURL := fullAuthorizeFlow(t, base)
	u, _ := url.Parse(redirectURL)
	code := u.Query().Get("code")

	tokenResp, err := http.PostForm(base+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"headscale"},
		"client_secret": {"secret123"},
		"redirect_uri":  {"http://localhost:9999/callback"},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokenResp.Body.Close()

	var token map[string]string
	json.NewDecoder(tokenResp.Body).Decode(&token)
	accessToken := token["access_token"]

	// Now call userinfo with the real access token
	req, _ := http.NewRequest("GET", base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["sub"] != "did:plc:placeholder" {
		t.Errorf("sub = %v", body["sub"])
	}
}

// --- PKCE tests ---

// fullAuthorizeFlowPKCE does the Phase 1 flow with PKCE.
// Returns the redirect URL (containing the code).
func fullAuthorizeFlowPKCE(t *testing.T, base, codeChallenge string) string {
	client := makeClient()

	resp, err := client.Get(base + "/authorize?client_id=headscale&redirect_uri=http://localhost:9999/callback&response_type=code&scope=openid+profile+email&state=test&code_challenge=" + codeChallenge + "&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("authorize GET: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("authorize GET status %d, want 200", resp.StatusCode)
	}

	resp, err = client.PostForm(base+"/authorize", url.Values{
		"phase1": {"true"},
	})
	if err != nil {
		t.Fatalf("authorize POST: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	idx := strings.Index(html, `window.location.href = "`)
	if idx == -1 {
		t.Fatalf("success page doesn't contain redirect URL: %s", html)
	}
	start := idx + len(`window.location.href = "`)
	end := strings.Index(html[start:], `"`)
	redirectURL := html[start : start+end]
	return redirectURL
}

func TestPKCEFlow(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	// Generate a real PKCE pair
	codeVerifier := "test-verifier-1234567890"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	redirectURL := fullAuthorizeFlowPKCE(t, base, codeChallenge)
	u, _ := url.Parse(redirectURL)
	code := u.Query().Get("code")

	// Valid verifier — should succeed
	tokenResp, err := http.PostForm(base+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"headscale"},
		"client_secret": {"secret123"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"code_verifier": {codeVerifier},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("valid PKCE: status %d: %s", tokenResp.StatusCode, body)
	}

	var token map[string]any
	json.NewDecoder(tokenResp.Body).Decode(&token)
	if _, ok := token["id_token"]; !ok {
		t.Error("no id_token in response")
	}
}

func TestPKCEInvalidVerifier(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	codeVerifier := "test-verifier-1234567890"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	redirectURL := fullAuthorizeFlowPKCE(t, base, codeChallenge)
	u, _ := url.Parse(redirectURL)
	code := u.Query().Get("code")

	// Invalid verifier — should fail
	tokenResp, err := http.PostForm(base+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"headscale"},
		"client_secret": {"secret123"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"code_verifier": {"wrong-verifier"},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 400 {
		t.Fatalf("status %d, want 400", tokenResp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(tokenResp.Body).Decode(&body)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

// --- WebFinger tests ---

func TestWebFingerNonAdminEmail(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	resp, err := http.Get(base + "/.well-known/webfinger?resource=acct:hello@mesh.glados.computer")
	if err != nil {
		t.Fatalf("get webfinger: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var wf struct {
		Subject string `json:"subject"`
		Links   []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}
	json.NewDecoder(resp.Body).Decode(&wf)
	if wf.Subject != "acct:hello@mesh.glados.computer" {
		t.Errorf("subject = %v", wf.Subject)
	}
	if len(wf.Links) != 1 || wf.Links[0].Href != "https://mesh.glados.computer" {
		t.Errorf("links = %v", wf.Links)
	}
}

func TestWebFingerWrongDomain(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	resp, err := http.Get(base + "/.well-known/webfinger?resource=acct:admin@evil.com")
	if err != nil {
		t.Fatalf("get webfinger: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestWebFingerMissingResource(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	resp, err := http.Get(base + "/.well-known/webfinger")
	if err != nil {
		t.Fatalf("get webfinger: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// --- Token edge cases ---

func TestTokenExpiredCode(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	// Insert an auth code with past expiry directly into the DB
	authReq := &db.OidcAuthCode{
		Code:                "expired-code-test",
		ClientId:            "headscale",
		RedirectUri:         "http://localhost:9999/callback",
		Scope:               "openid",
		Sub:                "did:plc:placeholder",
		PreferredUsername:   "placeholder",
		Email:              "admin@mesh.glados.computer",
		ExpiresAt:          time.Now().Add(-1 * time.Minute),
	}
	if err := s.db.DB.Create(authReq).Error; err != nil {
		t.Fatalf("create auth code: %v", err)
	}

	tokenResp, err := http.PostForm(base+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"expired-code-test"},
		"client_id":     {"headscale"},
		"client_secret": {"secret123"},
		"redirect_uri":  {"http://localhost:9999/callback"},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 400 {
		t.Fatalf("status %d, want 400", tokenResp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(tokenResp.Body).Decode(&body)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

func TestTokenMismatchedRedirectURI(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	redirectURL := fullAuthorizeFlow(t, base)
	u, _ := url.Parse(redirectURL)
	code := u.Query().Get("code")

	tokenResp, err := http.PostForm(base+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"headscale"},
		"client_secret": {"secret123"},
		"redirect_uri":  {"http://localhost:8888/different"},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 400 {
		t.Fatalf("status %d, want 400", tokenResp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(tokenResp.Body).Decode(&body)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

// --- Userinfo edge cases ---

func TestUserinfoNoToken(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	resp, err := http.Get(base + "/userinfo")
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestUserinfoInvalidToken(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	req, _ := http.NewRequest("GET", base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer fake-token-12345")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// --- Admin auth tests ---

func TestAdminLoginSuccess(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	client := makeClient()

	resp, err := client.PostForm(base+"/admin/login", url.Values{
		"token": {"test-admin-token"},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect to admin UI
	if resp.StatusCode != 303 {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
}

func TestAdminLoginWrongToken(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	resp, err := http.PostForm(base+"/admin/login", url.Values{
		"token": {"wrong-token"},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminLogout(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	client := makeClient()

	// Login first
	resp, err := client.PostForm(base+"/admin/login", url.Values{
		"token": {"test-admin-token"},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()

	// Logout
	resp, err = client.PostForm(base+"/admin/logout", nil)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect to login page
	if resp.StatusCode != 303 {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
}

// --- Whitelist CRUD tests ---

// adminClient creates a client that's logged in as admin.
func adminClient(t *testing.T, base string) *http.Client {
	client := makeClient()
	resp, err := client.PostForm(base+"/admin/login", url.Values{
		"token": {"test-admin-token"},
	})
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	resp.Body.Close()
	return client
}

func TestWhitelistAdd(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)
	client := adminClient(t, base)

	body := bytes.NewBufferString(`{"did":"did:plc:test123","handle":"test.bsky.social","max_nodes":3,"notes":"test entry"}`)
	req, _ := http.NewRequest("POST", base+"/api/v1/whitelist", body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	var entry db.WhitelistEntry
	json.NewDecoder(resp.Body).Decode(&entry)
	if entry.DID != "did:plc:test123" {
		t.Errorf("did = %v", entry.DID)
	}
	if entry.Handle != "test.bsky.social" {
		t.Errorf("handle = %v", entry.Handle)
	}
	if entry.MaxNodes != 3 {
		t.Errorf("max_nodes = %v", entry.MaxNodes)
	}
}

func TestWhitelistList(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)
	client := adminClient(t, base)

	// Add an entry first
	s.db.DB.Create(&db.WhitelistEntry{
		DID:      "did:plc:listtest",
		Handle:   "list.bsky.social",
		MaxNodes: 2,
		Notes:    "list test",
	})

	resp, err := client.Get(base + "/api/v1/whitelist")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var entries []db.WhitelistEntry
	json.NewDecoder(resp.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].DID != "did:plc:listtest" {
		t.Errorf("did = %v", entries[0].DID)
	}
}

func TestWhitelistDelete(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)
	client := adminClient(t, base)

	entry := db.WhitelistEntry{
		DID:      "did:plc:deletetest",
		Handle:   "delete.bsky.social",
		MaxNodes: 1,
	}
	s.db.DB.Create(&entry)

	req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/whitelist/%d", base, entry.ID), nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Verify it's gone
	var count int64
	s.db.DB.Model(&db.WhitelistEntry{}).Count(&count)
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestWhitelistUpdate(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)
	client := adminClient(t, base)

	entry := db.WhitelistEntry{
		DID:      "did:plc:updatetest",
		Handle:   "old.bsky.social",
		MaxNodes: 1,
		Notes:    "old notes",
	}
	s.db.DB.Create(&entry)

	body := bytes.NewBufferString(`{"handle":"new.bsky.social","max_nodes":5,"notes":"updated notes"}`)
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/whitelist/%d", base, entry.ID), body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var updated db.WhitelistEntry
	json.NewDecoder(resp.Body).Decode(&updated)
	if updated.Handle != "new.bsky.social" {
		t.Errorf("handle = %v, want new.bsky.social", updated.Handle)
	}
	if updated.MaxNodes != 5 {
		t.Errorf("max_nodes = %v, want 5", updated.MaxNodes)
	}
	if updated.Notes != "updated notes" {
		t.Errorf("notes = %v, want 'updated notes'", updated.Notes)
	}
}

func TestWhitelistUnauthorized(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	// No admin login — should get 401
	resp, err := http.Get(base + "/api/v1/whitelist")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWhitelistAddDuplicate(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)
	client := adminClient(t, base)

	s.db.DB.Create(&db.WhitelistEntry{
		DID:    "did:plc:duptest",
		Handle: "dup.bsky.social",
	})

	body := bytes.NewBufferString(`{"did":"did:plc:duptest","handle":"dup2.bsky.social"}`)
	req, _ := http.NewRequest("POST", base+"/api/v1/whitelist", body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 409 {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}
