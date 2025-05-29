package actions_oidc_test

import (
	"testing"

	"github.com/hosom/actions_oidc"
)

func TestActionsClaims_Match(t *testing.T) {
	tests := []struct {
		name     string
		claims1  actions_oidc.ActionsClaims
		claims2  actions_oidc.ActionsClaims
		expected bool
	}{
		{
			name:     "empty claims should match",
			claims1:  actions_oidc.ActionsClaims{},
			claims2:  actions_oidc.ActionsClaims{},
			expected: true,
		},
		{
			name: "matching environment",
			claims1: actions_oidc.ActionsClaims{
				Environment: "production",
			},
			claims2: actions_oidc.ActionsClaims{
				Environment: "production",
			},
			expected: true,
		},
		{
			name: "non-matching environment",
			claims1: actions_oidc.ActionsClaims{
				Environment: "production",
			},
			claims2: actions_oidc.ActionsClaims{
				Environment: "staging",
			},
			expected: false,
		},
		{
			name: "empty second claim environment should match",
			claims1: actions_oidc.ActionsClaims{
				Environment: "production",
			},
			claims2:  actions_oidc.ActionsClaims{},
			expected: true,
		},
		{
			name: "matching repository owner",
			claims1: actions_oidc.ActionsClaims{
				RepositoryOwner: "hosom",
			},
			claims2: actions_oidc.ActionsClaims{
				RepositoryOwner: "hosom",
			},
			expected: true,
		},
		{
			name: "non-matching repository owner",
			claims1: actions_oidc.ActionsClaims{
				RepositoryOwner: "hosom",
			},
			claims2: actions_oidc.ActionsClaims{
				RepositoryOwner: "other",
			},
			expected: false,
		},
		{
			name: "matching multiple fields",
			claims1: actions_oidc.ActionsClaims{
				Environment:     "production",
				Repository:      "hosom/repo",
				RepositoryOwner: "hosom",
				Actor:           "github-user",
			},
			claims2: actions_oidc.ActionsClaims{
				Environment:     "production",
				Repository:      "hosom/repo",
				RepositoryOwner: "hosom",
				Actor:           "github-user",
			},
			expected: true,
		},
		{
			name: "non-matching one of multiple fields",
			claims1: actions_oidc.ActionsClaims{
				Environment:     "production",
				Repository:      "hosom/repo",
				RepositoryOwner: "hosom",
				Actor:           "github-user",
			},
			claims2: actions_oidc.ActionsClaims{
				Environment:     "production",
				Repository:      "hosom/repo",
				RepositoryOwner: "other",
				Actor:           "github-user",
			},
			expected: false,
		},
		{
			name: "partial match with empty fields in second claim",
			claims1: actions_oidc.ActionsClaims{
				Environment:     "production",
				Repository:      "hosom/repo",
				RepositoryOwner: "hosom",
				Actor:           "github-user",
			},
			claims2: actions_oidc.ActionsClaims{
				Environment: "production",
				Repository:  "hosom/repo",
			},
			expected: true,
		},
		{
			name: "all fields matching",
			claims1: actions_oidc.ActionsClaims{
				Environment:          "production",
				Ref:                  "refs/heads/main",
				Sha:                  "abc123",
				Repository:           "hosom/repo",
				RepositoryOwner:      "hosom",
				ActorID:              "123456",
				RepositoryVisibility: "public",
				RepositoryID:         "789",
				RepositoryOwnerID:    "456",
				RunID:                "run123",
				RunNumber:            "1",
				RunAttempt:           "1",
				RunnerEnvironment:    "github-hosted",
				Actor:                "github-user",
				Workflow:             "CI",
				HeadRef:              "main",
				BaseRef:              "main",
				EventName:            "push",
				RefType:              "branch",
				JobWorkflowRef:       "hosom/repo/.github/workflows/ci.yml@refs/heads/main",
			},
			claims2: actions_oidc.ActionsClaims{
				Environment:          "production",
				Ref:                  "refs/heads/main",
				Sha:                  "abc123",
				Repository:           "hosom/repo",
				RepositoryOwner:      "hosom",
				ActorID:              "123456",
				RepositoryVisibility: "public",
				RepositoryID:         "789",
				RepositoryOwnerID:    "456",
				RunID:                "run123",
				RunNumber:            "1",
				RunAttempt:           "1",
				RunnerEnvironment:    "github-hosted",
				Actor:                "github-user",
				Workflow:             "CI",
				HeadRef:              "main",
				BaseRef:              "main",
				EventName:            "push",
				RefType:              "branch",
				JobWorkflowRef:       "hosom/repo/.github/workflows/ci.yml@refs/heads/main",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.claims1.Match(tt.claims2)
			if result != tt.expected {
				t.Errorf("Match() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

