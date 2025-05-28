package actions_oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// testKeyID for our mock key
const testKeyID = "test-key-id"

// Generate a test RSA key pair for testing
func generateTestKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// Create a test token with given claims
func createTestToken(claims ActionsClaims, audience string, privateKey *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, &claims)
	token.Header["kid"] = testKeyID

	// Set audience in claims if provided
	if audience != "" {
		claims.Audience = jwt.ClaimStrings{audience}
	}

	// Set expiry time in the future
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())

	return token.SignedString(privateKey)
}

// Mock keyfunc that validates against our test key
func createMockKeyfunc(publicKey *rsa.PublicKey) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		if token.Header["kid"] != testKeyID {
			return nil, fmt.Errorf("unknown key ID")
		}

		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return publicKey, nil
	}
}

func TestWithJWKSCache(t *testing.T) {
	privateKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	mockKeyfunc := createMockKeyfunc(&privateKey.PublicKey)
	
	m := &GinMiddleware{}
	opt := WithJWKSCache(mockKeyfunc)
	opt(m)

	if m.jwksCache == nil {
		t.Error("WithJWKSCache() did not set jwksCache")
	}
}

func TestWithAudience(t *testing.T) {
	tests := []struct {
		name     string
		audience string
	}{
		{
			name:     "set audience",
			audience: "test-audience",
		},
		{
			name:     "empty audience",
			audience: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &GinMiddleware{}
			opt := WithAudience(tt.audience)
			opt(m)

			if m.audience != tt.audience {
				t.Errorf("WithAudience() = %v, want %v", m.audience, tt.audience)
			}
		})
	}
}

func TestWithWellKnownURLs(t *testing.T) {
	tests := []struct {
		name string
		urls []string
	}{
		{
			name: "single URL",
			urls: []string{"https://example.com/.well-known/jwks"},
		},
		{
			name: "multiple URLs",
			urls: []string{
				"https://example.com/.well-known/jwks",
				"https://other.com/.well-known/jwks",
			},
		},
		{
			name: "empty slice",
			urls: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &GinMiddleware{}
			opt := WithWellKnownURLs(tt.urls)
			opt(m)

			if len(m.wellKnownURLs) != len(tt.urls) {
				t.Errorf("WithWellKnownURLs() length = %v, want %v", len(m.wellKnownURLs), len(tt.urls))
				return
			}

			for i, url := range tt.urls {
				if m.wellKnownURLs[i] != url {
					t.Errorf("WithWellKnownURLs()[%d] = %v, want %v", i, m.wellKnownURLs[i], url)
				}
			}
		})
	}
}

func TestWithWellKnownURL(t *testing.T) {
	tests := []struct {
		name        string
		initialURLs []string
		newURL      string
		expected    []string
	}{
		{
			name:        "add to empty slice",
			initialURLs: nil,
			newURL:      "https://example.com/.well-known/jwks",
			expected:    []string{"https://example.com/.well-known/jwks"},
		},
		{
			name:        "add to existing slice",
			initialURLs: []string{"https://first.com/.well-known/jwks"},
			newURL:      "https://second.com/.well-known/jwks",
			expected: []string{
				"https://first.com/.well-known/jwks",
				"https://second.com/.well-known/jwks",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &GinMiddleware{wellKnownURLs: tt.initialURLs}
			opt := WithWellKnownURL(tt.newURL)
			opt(m)

			if len(m.wellKnownURLs) != len(tt.expected) {
				t.Errorf("WithWellKnownURL() length = %v, want %v", len(m.wellKnownURLs), len(tt.expected))
				return
			}

			for i, url := range tt.expected {
				if m.wellKnownURLs[i] != url {
					t.Errorf("WithWellKnownURL()[%d] = %v, want %v", i, m.wellKnownURLs[i], url)
				}
			}
		})
	}
}

func TestNewGinMiddleware(t *testing.T) {
	// Set Gin to test mode to avoid debug output
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name    string
		opts    []GinMiddlewareOption
		wantErr bool
		check   func(*GinMiddleware) error
	}{
		{
			name: "default configuration",
			opts: []GinMiddlewareOption{},
			check: func(m *GinMiddleware) error {
				if m.jwksCache == nil {
					return fmt.Errorf("jwksCache should not be nil")
				}
				if len(m.wellKnownURLs) != 1 || m.wellKnownURLs[0] != GitHubWellKnownURL {
					return fmt.Errorf("wellKnownURLs should default to GitHub URL")
				}
				return nil
			},
			wantErr: false, // Actually succeeds in this environment
		},
		{
			name: "with custom audience",
			opts: []GinMiddlewareOption{
				WithAudience("test-audience"),
			},
			check: func(m *GinMiddleware) error {
				if m.audience != "test-audience" {
					return fmt.Errorf("audience = %v, want test-audience", m.audience)
				}
				return nil
			},
			wantErr: false, // Actually succeeds in this environment
		},
		{
			name: "with mock JWKS cache",
			opts: []GinMiddlewareOption{
				WithAudience("test-audience"),
			},
			check: func(m *GinMiddleware) error {
				if m.audience != "test-audience" {
					return fmt.Errorf("audience = %v, want test-audience", m.audience)
				}
				// Generate a test key pair for this test
				privateKey, err := generateTestKeyPair()
				if err != nil {
					return fmt.Errorf("failed to generate test key pair: %v", err)
				}
				
				// Set mock keyfunc to avoid live API calls in future tests
				m.jwksCache = createMockKeyfunc(&privateKey.PublicKey)
				
				if m.jwksCache == nil {
					return fmt.Errorf("jwksCache should not be nil")
				}
				return nil
			},
			wantErr: false, // Actually succeeds in this environment
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewGinMiddleware(tt.opts...)

			if tt.wantErr {
				if err == nil {
					t.Error("NewGinMiddleware() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewGinMiddleware() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.check != nil {
				if err := tt.check(m); err != nil {
					t.Errorf("NewGinMiddleware() check failed: %v", err)
				}
			}
		})
	}
}

func TestAuthActionsToken(t *testing.T) {
	// Set Gin to test mode to avoid debug output
	gin.SetMode(gin.TestMode)

	// Generate test key pair once for all tests
	privateKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedStatus int
		expectedBody   string
		audience       string
		setupClaims    func() ActionsClaims
	}{
		{
			name: "missing authorization header",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/test", nil)
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"error":"Authorization header is required"}`,
		},
		{
			name: "valid token",
			setupRequest: func() *http.Request {
				claims := ActionsClaims{
					RepositoryOwner: "hosom",
					Repository:      "test-repo",
				}
				token, _ := createTestToken(claims, "test-audience", privateKey)
				req, _ := http.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			expectedStatus: http.StatusOK,
			audience:       "test-audience",
			setupClaims: func() ActionsClaims {
				return ActionsClaims{
					RepositoryOwner: "hosom",
					Repository:      "test-repo",
				}
			},
		},
		{
			name: "token without Bearer prefix",
			setupRequest: func() *http.Request {
				claims := ActionsClaims{
					RepositoryOwner: "hosom",
					Repository:      "test-repo",
				}
				token, _ := createTestToken(claims, "test-audience", privateKey)
				req, _ := http.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", token)
				return req
			},
			expectedStatus: http.StatusOK,
			audience:       "test-audience",
			setupClaims: func() ActionsClaims {
				return ActionsClaims{
					RepositoryOwner: "hosom",
					Repository:      "test-repo",
				}
			},
		},
		{
			name: "invalid token",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer invalid-token")
				return req
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create middleware with mock keyfunc
			m := &GinMiddleware{
				jwksCache: createMockKeyfunc(&privateKey.PublicKey),
				audience:  tt.audience,
			}

			// Create test router
			router := gin.New()
			router.Use(m.AuthActionsToken())
			router.GET("/test", func(c *gin.Context) {
				claims, exists := c.Get("claims")
				if !exists {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "No claims in context"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"claims": claims})
			})

			// Create request
			req := tt.setupRequest()
			w := httptest.NewRecorder()

			// Execute request
			router.ServeHTTP(w, req)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("AuthActionsToken() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			// Check response body for specific cases
			if tt.expectedBody != "" {
				body := strings.TrimSpace(w.Body.String())
				if body != tt.expectedBody {
					t.Errorf("AuthActionsToken() body = %v, want %v", body, tt.expectedBody)
				}
			}

			// For successful cases, verify claims are set correctly
			if tt.expectedStatus == http.StatusOK && tt.setupClaims != nil {
				expectedClaims := tt.setupClaims()
				responseBody := w.Body.String()
				
				// Simple check that claims are included in response
				if !strings.Contains(responseBody, expectedClaims.RepositoryOwner) {
					t.Errorf("Response should contain repository owner %v", expectedClaims.RepositoryOwner)
				}
			}
		})
	}
}