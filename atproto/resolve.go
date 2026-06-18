package atproto

import (
	"fmt"
	"net/http"
)

// ResolveHandle resolves an AT Protocol handle to a DID.
// It tries DNS TXT lookup first, then HTTPS well-known.
func ResolveHandle(handle string) (string, error) {
	// Try DNS TXT: _atproto.handle → did=did:plc:...
	did, err := resolveDNS(handle)
	if err == nil {
		return did, nil
	}

	// Try HTTPS well-known: https://handle/.well-known/atproto-did
	did, err = resolveWellKnown(handle)
	if err == nil {
		return did, nil
	}

	return "", fmt.Errorf("could not resolve handle %q: dns: %w; well-known: failed", handle, err)
}

func resolveDNS(handle string) (string, error) {
	// TODO: DNS TXT lookup for _atproto.<handle>
	// Returns did=did:plc:... record
	return "", fmt.Errorf("not implemented")
}

func resolveWellKnown(handle string) (string, error) {
	url := fmt.Sprintf("https://%s/.well-known/atproto-did", handle)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("well-known request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("well-known returned status %d", resp.StatusCode)
	}

	// Body should be: did:plc:...
	var buf [1024]byte
	n, _ := resp.Body.Read(buf[:])
	did := string(buf[:n])

	// Trim whitespace
	did = trimSpace(did)

	if !isValidDID(did) {
		return "", fmt.Errorf("invalid DID from well-known: %q", did)
	}

	return did, nil
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func isValidDID(did string) bool {
	return len(did) > 8 && (did[:8] == "did:plc:" || did[:8] == "did:web:")
}
