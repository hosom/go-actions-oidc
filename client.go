package actions_oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func TokenRequest(aud string) (*http.Request, error) {
	Url := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	req, err := http.NewRequest(http.MethodGet, Url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+requestToken)
	if aud != "" {
		// Set the audience parameter in the query string
		query := req.URL.Query()
		query.Set("audience", aud)
		req.URL.RawQuery = query.Encode()
	}
	return req, nil
}

// RequestToken is a function that creates a new HTTP GET reques
func RequestToken(aud string) (string, error) {
	req, err := TokenRequest(aud)
	if err != nil {
		return "", err
	}

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return "", nil
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error response from server: %s", resp.Status)
	}
	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("error decoding response: %v", err)
	}
	return tokenResponse.Value, nil
}
