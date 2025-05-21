# actions_oidc
GitHub Actions OIDC client and validation

## Examples

This repository includes example usage for both the OIDC client and a Gin middleware for token validation.

### Client Example

The client example demonstrates how to request an OIDC token from GitHub Actions.

**Path:** `cmd/example/client/main.go`

```go
package main

import (
	"io"
	"log"
	"net/http"
	"os"

	"github.com/hosom/actions_oidc"
)

func main() {
	// Example usage of the actions_oidc package
	aud := "example-audience"
	token, err := actions_oidc.RequestToken(aud)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Token request successful")

	// use the returned token
	client := http.DefaultClient
	req, err := http.NewRequest(http.MethodGet, os.Getenv("TEST_URL"), nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Error response from server:", resp.Status)

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Response body:", string(bodyBytes))
	}

}
```

### Middleware Example

The middleware example shows how to use the Gin middleware to authenticate requests using an OIDC token. It checks for a specific audience and repository owner.

**Path:** `cmd/example/middleware/main.go`

```go
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hosom/actions_oidc"
)

func main() {
	aud := "example-audience"

	m, err := actions_oidc.NewGinMiddleware(actions_oidc.WithAudience(aud))
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()

	r.Group("/api").Use(m.AuthActionsToken()).GET("/test", func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No claims found"})
			return
		}

		if claims.(*actions_oidc.ActionsClaims).RepositoryOwner != "hosom" {
			log.Println("Invalid repository owner")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid repository owner"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"claims": claims})
	})

	r.Run(":8000")
}
```

