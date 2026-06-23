package oidc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type ProviderArgs struct {
	Hostname   string
	PrivateKey *ecdsa.PrivateKey
	JwkKey     jwk.Key
}

type Provider struct {
	hostname   string
	privateKey *ecdsa.PrivateKey
	jwkKey     jwk.Key
}

func NewProvider(args *ProviderArgs) *Provider {
	return &Provider{
		hostname:   args.Hostname,
		privateKey: args.PrivateKey,
		jwkKey:     args.JwkKey,
	}
}

// Discovery returns the OIDC discovery document
func (p *Provider) Discovery() map[string]interface{} {
	issuer := fmt.Sprintf("https://%s", p.hostname)
	return map[string]interface{}{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/authorize",
		"token_endpoint":         issuer + "/token",
		"userinfo_endpoint":      issuer + "/userinfo",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
		"response_types_supported": []string{
			"code",
		},
		"subject_types_supported": []string{
			"public",
		},
		"id_token_signing_alg_values_supported": []string{
			"ES256",
		},
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},
		"claims_supported": []string{
			"sub",
			"name",
			"preferred_username",
			"email",
		},
		"code_challenge_methods_supported": []string{
			"S256",
		},
	}
}

// JWKS returns the JSON Web Key Set
func (p *Provider) JWKS() (map[string]interface{}, error) {
	pubKey, err := jwk.PublicKeyOf(p.jwkKey)
	if err != nil {
		return nil, fmt.Errorf("error getting public key: %w", err)
	}

	keySet := jwk.NewSet()
	if err := keySet.AddKey(pubKey); err != nil {
		return nil, fmt.Errorf("error adding key to set: %w", err)
	}

	data, err := json.Marshal(keySet)
	if err != nil {
		return nil, fmt.Errorf("error marshaling key set: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("error unmarshaling key set: %w", err)
	}

	return result, nil
}

// IssueIDToken creates a signed JWT id_token
func (p *Provider) IssueIDToken(sub string, preferredUsername string, email string, audience string, nonce string) (string, error) {
	issuer := fmt.Sprintf("https://%s", p.hostname)

	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject(sub).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(1 * time.Hour)).
		Claim("preferred_username", preferredUsername).
		Claim("email", email).
		Claim("name", preferredUsername).
		Claim("nonce", nonce).
		Build()
	if err != nil {
		return "", fmt.Errorf("error building token: %w", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, p.jwkKey))
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}

	return string(signed), nil
}

// GenerateAuthCode generates a random authorization code
func GenerateAuthCode() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
