package headscale

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	baseUrl    string
	apiKey     string
	httpClient *http.Client
}

func NewClient(baseUrl string, apiKey string) *Client {
	return &Client{
		baseUrl:    baseUrl,
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

func (c *Client) doRequest(method string, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("error marshaling request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.baseUrl+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("headscale API error (%d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// DeleteUser removes a user and all their nodes from Headscale
func (c *Client) DeleteUser(userId string) error {
	_, err := c.doRequest("DELETE", "/api/v1/user/"+userId, nil)
	return err
}

// ListUsers returns all users in Headscale
func (c *Client) ListUsers() ([]byte, error) {
	return c.doRequest("GET", "/api/v1/user", nil)
}
