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
