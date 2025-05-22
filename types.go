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

// Match compares two ActionsClaims objects and returns true if they match
// on all reasonably comparable fields that are not empty in the second object.
// This is useful for checking if a token is valid for a given set of claims.
func (x *ActionsClaims) Match(y ActionsClaims) bool {
	switch {
	case !equal(x.Environment, y.Environment) && notZero(y.Environment):
		return false
	case !equal(x.Ref, y.Ref) && notZero(y.Ref):
		return false
	case !equal(x.Sha, y.Sha) && notZero(y.Sha):
		return false
	case !equal(x.Repository, y.Repository) && notZero(y.Repository):
		return false
	case !equal(x.RepositoryOwner, y.RepositoryOwner) && notZero(y.RepositoryOwner):
		return false
	case !equal(x.ActorID, y.ActorID) && notZero(y.ActorID):
		return false
	case !equal(x.RepositoryVisibility, y.RepositoryVisibility) && notZero(y.RepositoryVisibility):
		return false
	case !equal(x.RepositoryID, y.RepositoryID) && notZero(y.RepositoryID):
		return false
	case !equal(x.RepositoryOwnerID, y.RepositoryOwnerID) && notZero(y.RepositoryOwnerID):
		return false
	case !equal(x.RunID, y.RunID) && notZero(y.RunID):
		return false
	case !equal(x.RunNumber, y.RunNumber) && notZero(y.RunNumber):
		return false
	case !equal(x.RunAttempt, y.RunAttempt) && notZero(y.RunAttempt):
		return false
	case !equal(x.RunnerEnvironment, y.RunnerEnvironment) && notZero(y.RunnerEnvironment):
		return false
	case !equal(x.Actor, y.Actor) && notZero(y.Actor):
		return false
	case !equal(x.Workflow, y.Workflow) && notZero(y.Workflow):
		return false
	case !equal(x.HeadRef, y.HeadRef) && notZero(y.HeadRef):
		return false
	case !equal(x.BaseRef, y.BaseRef) && notZero(y.BaseRef):
		return false
	case !equal(x.EventName, y.EventName) && notZero(y.EventName):
		return false
	case !equal(x.RefType, y.RefType) && notZero(y.RefType):
		return false
	case !equal(x.JobWorkflowRef, y.JobWorkflowRef) && notZero(y.JobWorkflowRef):
		return false
	default:
		return true
	}
}

// equal checks if two values of the same type are equal.
// This is a generic function that works for any comparable type.
func equal[T comparable](a, b T) bool {
	return a == b
}

// notZero checks if the value is not the zero value of its type.
// This is a generic function that works for any comparable type.
func notZero[T comparable](a T) bool {
	var zero T
	return a != zero
}
