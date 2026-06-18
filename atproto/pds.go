package atproto

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ResolvePDSEndpoint resolves a DID to its PDS (Personal Data Server) URL.
// For did:plc, it queries the PLC directory.
// For did:web, it fetches the did:web document.
func ResolvePDSEndpoint(did string) (string, error) {
	if len(did) >= 8 && did[:8] == "did:plc:" {
		return resolvePLC(did)
	}
	if len(did) >= 8 && did[:8] == "did:web:" {
		return resolveDidWeb(did)
	}
	return "", fmt.Errorf("unsupported DID method: %s", did)
}

func resolvePLC(did string) (string, error) {
	url := fmt.Sprintf("https://plc.directory/%s", did)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("PLC directory request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("PLC directory returned status %d", resp.StatusCode)
	}

	var doc struct {
		AlsoKnownAs []string `json:"alsoKnownAs"`
		Service     []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
			// ServiceEndpoint can be string or object
			ServiceEndpoint interface{} `json:"serviceEndpoint"`
		} `json:"service"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("error decoding PLC document: %w", err)
	}

	for _, svc := range doc.Service {
		if svc.Type == "AtprotoPersonalDataServer" || svc.ID == "#atproto_pds" {
			switch v := svc.ServiceEndpoint.(type) {
			case string:
				return v, nil
			default:
				return fmt.Sprintf("%v", v), nil
			}
		}
	}

	return "", fmt.Errorf("no PDS service found in PLC document for %s", did)
}

func resolveDidWeb(did string) (string, error) {
	// did:web:example.com → https://example.com/.well-known/did.json
	domain := did[8:]
	url := fmt.Sprintf("https://%s/.well-known/did.json", domain)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("did:web request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("did:web returned status %d", resp.StatusCode)
	}

	var doc struct {
		Service []struct {
			ID              string      `json:"id"`
			Type            string      `json:"type"`
			ServiceEndpoint interface{} `json:"serviceEndpoint"`
		} `json:"service"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("error decoding did:web document: %w", err)
	}

	for _, svc := range doc.Service {
		if svc.Type == "AtprotoPersonalDataServer" {
			switch v := svc.ServiceEndpoint.(type) {
			case string:
				return v, nil
			default:
				return fmt.Sprintf("%v", v), nil
			}
		}
	}

	return "", fmt.Errorf("no PDS service found in did:web document for %s", did)
}
