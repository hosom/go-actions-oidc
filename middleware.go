package actions_oidc

import (
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	GitHubWellKnownURL = "https://token.actions.githubusercontent.com/.well-known/jwks"
)

// Implement Gin middleware for JWT validation
type GinMiddleware struct {
	jwksCache     jwt.Keyfunc
	audience      string
	wellKnownURLs []string
}

type GinMiddlewareOption func(*GinMiddleware)

func WithJWKSCache(jwksCache jwt.Keyfunc) GinMiddlewareOption {
	return func(m *GinMiddleware) {
		m.jwksCache = jwksCache
	}
}

func WithAudience(audience string) GinMiddlewareOption {
	return func(m *GinMiddleware) {
		m.audience = audience
	}
}

func WithWellKnownURLs(urls []string) GinMiddlewareOption {
	return func(m *GinMiddleware) {
		m.wellKnownURLs = urls
	}
}

func WithWellKnownURL(url string) GinMiddlewareOption {
	return func(m *GinMiddleware) {
		if m.wellKnownURLs != nil {
			m.wellKnownURLs = append(m.wellKnownURLs, url)
		} else {
			// Initialize the slice if it's nil
			m.wellKnownURLs = []string{url}
		}
	}
}

func NewGinMiddleware(opts ...GinMiddlewareOption) (*GinMiddleware, error) {
	m := &GinMiddleware{
		jwksCache:     nil,
		audience:      "",
		wellKnownURLs: []string{},
	}

	for _, opt := range opts {
		opt(m)
	}

	// Default to at least the GitHub well-known URL if none are provided
	if len(m.wellKnownURLs) == 0 {
		m.wellKnownURLs = []string{GitHubWellKnownURL}
	}

	if m.jwksCache == nil {
		k, err := keyfunc.NewDefault(m.wellKnownURLs)
		if err != nil {
			return nil, err
		}
		m.jwksCache = k.Keyfunc
	}

	return m, nil
}

func (m *GinMiddleware) AuthActionsToken() gin.HandlerFunc {
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
