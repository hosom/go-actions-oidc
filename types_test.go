package actions_oidc

import (
	"testing"
)

func TestActionsClaims_Match(t *testing.T) {
	tests := []struct {
		name     string
		claims1  ActionsClaims
		claims2  ActionsClaims
		expected bool
	}{
		{
			name:     "empty claims should match",
			claims1:  ActionsClaims{},
			claims2:  ActionsClaims{},
			expected: true,
		},
		{
			name: "matching environment",
			claims1: ActionsClaims{
				Environment: "production",
			},
			claims2: ActionsClaims{
				Environment: "production",
			},
			expected: true,
		},
		{
			name: "non-matching environment",
			claims1: ActionsClaims{
				Environment: "production",
			},
			claims2: ActionsClaims{
				Environment: "staging",
			},
			expected: false,
		},
		{
			name: "empty second claim environment should match",
			claims1: ActionsClaims{
				Environment: "production",
			},
			claims2:  ActionsClaims{},
			expected: true,
		},
		{
			name: "matching repository owner",
			claims1: ActionsClaims{
				RepositoryOwner: "hosom",
			},
			claims2: ActionsClaims{
				RepositoryOwner: "hosom",
			},
			expected: true,
		},
		{
			name: "non-matching repository owner",
			claims1: ActionsClaims{
				RepositoryOwner: "hosom",
			},
			claims2: ActionsClaims{
				RepositoryOwner: "other",
			},
			expected: false,
		},
		{
			name: "matching multiple fields",
			claims1: ActionsClaims{
				Environment:     "production",
				Repository:      "hosom/repo",
				RepositoryOwner: "hosom",
				Actor:           "github-user",
			},
			claims2: ActionsClaims{
				Environment:     "production",
				Repository:      "hosom/repo",
				RepositoryOwner: "hosom",
				Actor:           "github-user",
			},
			expected: true,
		},
		{
			name: "non-matching one of multiple fields",
			claims1: ActionsClaims{
				Environment:     "production",
				Repository:      "hosom/repo",
				RepositoryOwner: "hosom",
				Actor:           "github-user",
			},
			claims2: ActionsClaims{
				Environment:     "production",
				Repository:      "hosom/repo",
				RepositoryOwner: "other",
				Actor:           "github-user",
			},
			expected: false,
		},
		{
			name: "partial match with empty fields in second claim",
			claims1: ActionsClaims{
				Environment:     "production",
				Repository:      "hosom/repo",
				RepositoryOwner: "hosom",
				Actor:           "github-user",
			},
			claims2: ActionsClaims{
				Environment: "production",
				Repository:  "hosom/repo",
			},
			expected: true,
		},
		{
			name: "all fields matching",
			claims1: ActionsClaims{
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
			claims2: ActionsClaims{
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

func TestEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        interface{}
		b        interface{}
		expected bool
	}{
		{
			name:     "equal strings",
			a:        "test",
			b:        "test",
			expected: true,
		},
		{
			name:     "different strings",
			a:        "test1",
			b:        "test2",
			expected: false,
		},
		{
			name:     "equal ints",
			a:        42,
			b:        42,
			expected: true,
		},
		{
			name:     "different ints",
			a:        42,
			b:        43,
			expected: false,
		},
		{
			name:     "empty strings",
			a:        "",
			b:        "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch a := tt.a.(type) {
			case string:
				result := equal(a, tt.b.(string))
				if result != tt.expected {
					t.Errorf("equal(%v, %v) = %v, expected %v", tt.a, tt.b, result, tt.expected)
				}
			case int:
				result := equal(a, tt.b.(int))
				if result != tt.expected {
					t.Errorf("equal(%v, %v) = %v, expected %v", tt.a, tt.b, result, tt.expected)
				}
			}
		})
	}
}

func TestNotZero(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected bool
	}{
		{
			name:     "non-empty string",
			value:    "test",
			expected: true,
		},
		{
			name:     "empty string",
			value:    "",
			expected: false,
		},
		{
			name:     "non-zero int",
			value:    42,
			expected: true,
		},
		{
			name:     "zero int",
			value:    0,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch v := tt.value.(type) {
			case string:
				result := notZero(v)
				if result != tt.expected {
					t.Errorf("notZero(%v) = %v, expected %v", tt.value, result, tt.expected)
				}
			case int:
				result := notZero(v)
				if result != tt.expected {
					t.Errorf("notZero(%v) = %v, expected %v", tt.value, result, tt.expected)
				}
			}
		})
	}
}