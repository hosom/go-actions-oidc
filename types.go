package actions_oidc

import (
	"github.com/golang-jwt/jwt/v5"
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
