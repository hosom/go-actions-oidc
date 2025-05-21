package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

type TokenResponse struct {
	Value string `json:"value,omitempty"`
}

func TokenRequest(aud string) (*http.Request, error) {
	Url := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	req, err := http.NewRequest(http.MethodGet, Url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+requestToken)
	if aud != "" {
		req.URL.Query().Set("audience", aud)
	}
	return req, nil
}

func main() {
	// Example usage of TokenRequest
	aud := "example-audience"

	req, err := TokenRequest(aud)
	if err != nil {
		log.Fatalf("Error creating token request: %v", err)
	}

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Error response from server: %s", resp.Status)
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		log.Fatalf("Error decoding response: %v", err)
	}

	fmt.Printf("Token: %s\n", tokenResponse.Value)

	req, err = http.NewRequest(http.MethodGet, os.Getenv("TEST_URL"), nil)
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+tokenResponse.Value)
	resp, err = client.Do(req)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Error response from server: %s", resp.Status)
	}
}
