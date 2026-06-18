package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/govi218/at-mesh/internal/db"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestServer(t *testing.T) *Server {
	t.Helper()

	gormDb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormDb.AutoMigrate(&db.AuthRequest{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	args := &Args{
		Addr:          "127.0.0.1:0",
		Hostname:      "mesh.glados.computer",
		JwkPath:       "../keys/jwk.key",
		DbName:        ":memory:",
		AdminEmail:    "admin@mesh.glados.computer",
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

	// Use httptest instead of real listener
	// But Server.Serve() needs a real listener, so we'll just use the echo handler
	// Actually, let's just start it on a random port
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

	var doc map[string]interface{}
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
			Rel string `json:"rel"`
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

func TestAuthorizeValidClient(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // don't follow redirects
	}}

	resp, err := client.Get(base + "/authorize?client_id=headscale&redirect_uri=http://localhost:9999/callback&response_type=code&scope=openid+profile+email&state=test123")
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 303 {
		t.Fatalf("status %d, want 303", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("no Location header")
	}
	if !strings.Contains(loc, "http://localhost:9999/callback?code=") {
		t.Errorf("redirect = %v, want callback with code", loc)
	}
	if !strings.Contains(loc, "state=test123") {
		t.Errorf("state not preserved in %v", loc)
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

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
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

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if !strings.Contains(body["error_description"], "redirect_uri") {
		t.Errorf("error_description = %v, want redirect_uri mention", body["error_description"])
	}
}

func TestTokenExchange(t *testing.T) {
	s := setupTestServer(t)
	base := startTestServer(t, s)

	// Get a code first
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(base + "/authorize?client_id=headscale&redirect_uri=http://localhost:9999/callback&response_type=code&scope=openid+profile+email&state=test")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")

	// Exchange code for token
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

	var token map[string]interface{}
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

	// Get a code
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(base + "/authorize?client_id=headscale&redirect_uri=http://localhost:9999/callback&response_type=code&scope=openid&state=test")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")

	// Exchange with wrong secret
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

	// Get a code
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(base + "/authorize?client_id=headscale&redirect_uri=http://localhost:9999/callback&response_type=code&scope=openid&state=test")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	u, _ := url.Parse(loc)
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

	req, _ := http.NewRequest("GET", base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer test-token")

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
