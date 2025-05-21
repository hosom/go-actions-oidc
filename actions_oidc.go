package actions_oidc

/*
import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
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

type GitHubActionsJWTMiddleware struct {
	jwksCache jwt.Keyfunc
	audience  string
}

func (m *GitHubActionsJWTMiddleware) AuthActionsToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.Request.Header.Get("Authorization")
		if tokenStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Trim the "Bearer " prefix if present
		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")

		token, err := jwt.ParseWithClaims(tokenStr, &ActionsClaims{}, m.jwksCache, jwt.WithAudience(m.audience))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(*ActionsClaims); ok && token.Valid {
			// Token is valid, set claims in context
			c.Set("claims", claims)
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
		}
	}
}

func main() {
	// Initialize a new JWKS cache
	k, err := keyfunc.NewDefault([]string{GitHubWellKnownURL})
	if err != nil {
		log.Fatal(err)
	}

	m := GitHubActionsJWTMiddleware{
		jwksCache: k.Keyfunc,
		audience:  "example-audience",
	}

	r := gin.Default()

	r.Group("/api").Use(m.AuthActionsToken()).GET("/test", func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No claims found"})
			return
		}

		if claims.(*ActionsClaims).RepositoryOwner != "hosom" {
			log.Println("Invalid repository owner")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid repository owner"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"claims": claims})
	})

	r.Run(":8000")
}
*/
