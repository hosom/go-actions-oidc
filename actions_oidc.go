package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

const (
	GitHubWellKnownURL = "https://token.actions.githubusercontent.com/.well-known/jwks"
)

type ActionsClaims struct {
	// RegisteredClaims are the standard claims required by the JWT spec
	jwt.RegisteredClaims
	Environment          string `json:"environment,omitempty"`
	Ref                  string `json:"ref,omitempty"`
	Sha                  string `json:"sha,omitempty"`
	Repository           string `json:"repository,omitempty"`
	RepositoryOwner      string `json:"repository_owner,omitempty"`
	ActorID              string `json:"actor_id,omitempty"`
	RepositoryVisibility string `json:"repository_visibility,omitempty"`
	RepositoryID         string `json:"repository_id,omitempty"`
	RepositoryOwnerID    string `json:"repository_owner_id,omitempty"`
	RunID                string `json:"run_id,omitempty"`
	RunNumber            string `json:"run_number,omitempty"`
	RunAttempt           string `json:"run_attempt,omitempty"`
	RunnerEnvironment    string `json:"runner_environment,omitempty"`
	Actor                string `json:"actor,omitempty"`
	Workflow             string `json:"workflow,omitempty"`
	HeadRef              string `json:"head_ref,omitempty"`
	BaseRef              string `json:"base_ref,omitempty"`
	EventName            string `json:"event_name,omitempty"`
	RefType              string `json:"ref_type,omitempty"`
	JobWorkflowRef       string `json:"job_workflow_ref,omitempty"`
}

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

	req, err := TokenRequest("https://my-domain.com")
	if err != nil {
		log.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Failed to get token: %s", resp.Status)
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		log.Fatal(err)
	}

	k, err := keyfunc.NewDefault([]string{GitHubWellKnownURL})
	if err != nil {
		log.Fatal(err)
	}

	tokenStr := tokenResponse.Value

	token, err := jwt.ParseWithClaims(tokenStr, &ActionsClaims{}, k.Keyfunc)
	if err != nil {
		log.Fatal(err)
	}

	if claims, ok := token.Claims.(*ActionsClaims); ok && token.Valid {
		log.Printf("Token is valid. Claims: %+v\n", claims)
	} else {
		log.Println("Token is invalid.")
	}
}
