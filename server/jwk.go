package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// CreateJwk generates a new ECDSA P-256 private key and writes it as JWK to the given path
func CreateJwk(outPath string) error {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating key: %w", err)
	}

	key, err := jwk.FromRaw(privKey)
	if err != nil {
		return fmt.Errorf("error creating JWK: %w", err)
	}

	kid := fmt.Sprintf("%d", time.Now().Unix())
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return fmt.Errorf("error setting key ID: %w", err)
	}

	if err := key.Set(jwk.AlgorithmKey, "ES256"); err != nil {
		return fmt.Errorf("error setting algorithm: %w", err)
	}

	b, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("error marshaling JWK: %w", err)
	}

	if err := os.WriteFile(outPath, b, 0644); err != nil {
		return fmt.Errorf("error writing JWK file: %w", err)
	}

	fmt.Printf("JWK written to %s (kid: %s)\n", outPath, kid)
	return nil
}
