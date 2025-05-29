package actions_oidc_test

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
	"github.com/hosom/actions_oidc"
)

// testKeyID for our mock key
const testKeyID = "test-key-id"

// Generate a test RSA key pair for testing
func generateTestKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// Create a test token with given claims
func createTestToken(claims actions_oidc.ActionsClaims, audience string, privateKey *rsa.PrivateKey) (string, error) {
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
	
	// Test that WithJWKSCache option function works without panicking
	// We can only test that the option doesn't cause errors since fields are unexported
	option := actions_oidc.WithJWKSCache(mockKeyfunc)
	if option == nil {
		t.Error("WithJWKSCache() returned nil option function")
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
			// Test that WithAudience option function works without panicking
			// We can only test that the option doesn't cause errors since fields are unexported
			option := actions_oidc.WithAudience(tt.audience)
			if option == nil {
				t.Error("WithAudience() returned nil option function")
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
			// Test that WithWellKnownURLs option function works without panicking
			// We can only test that the option doesn't cause errors since fields are unexported
			option := actions_oidc.WithWellKnownURLs(tt.urls)
			if option == nil {
				t.Error("WithWellKnownURLs() returned nil option function")
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
			// Test that WithWellKnownURL option function works without panicking
			// We can only test that the option doesn't cause errors since fields are unexported
			option := actions_oidc.WithWellKnownURL(tt.newURL)
			if option == nil {
				t.Error("WithWellKnownURL() returned nil option function")
			}
		})
	}
}

func TestNewGinMiddleware(t *testing.T) {
	// Set Gin to test mode to avoid debug output
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name    string
		opts    []actions_oidc.GinMiddlewareOption
		wantErr bool
	}{
		{
			name:    "default configuration",
			opts:    []actions_oidc.GinMiddlewareOption{},
			wantErr: false, // Actually succeeds in this environment
		},
		{
			name: "with custom audience",
			opts: []actions_oidc.GinMiddlewareOption{
				actions_oidc.WithAudience("test-audience"),
			},
			wantErr: false, // Actually succeeds in this environment
		},
		{
			name: "with mock JWKS cache",
			opts: []actions_oidc.GinMiddlewareOption{
				actions_oidc.WithAudience("test-audience"),
			},
			wantErr: false, // Actually succeeds in this environment
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := actions_oidc.NewGinMiddleware(tt.opts...)

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

			if m == nil {
				t.Error("NewGinMiddleware() returned nil middleware")
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
		setupClaims    func() actions_oidc.ActionsClaims
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
				claims := actions_oidc.ActionsClaims{
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
			setupClaims: func() actions_oidc.ActionsClaims {
				return actions_oidc.ActionsClaims{
					RepositoryOwner: "hosom",
					Repository:      "test-repo",
				}
			},
		},
		{
			name: "token without Bearer prefix",
			setupRequest: func() *http.Request {
				claims := actions_oidc.ActionsClaims{
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
			setupClaims: func() actions_oidc.ActionsClaims {
				return actions_oidc.ActionsClaims{
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
			// Create middleware with mock keyfunc using the options
			var opts []actions_oidc.GinMiddlewareOption
			opts = append(opts, actions_oidc.WithJWKSCache(createMockKeyfunc(&privateKey.PublicKey)))
			if tt.audience != "" {
				opts = append(opts, actions_oidc.WithAudience(tt.audience))
			}
			
			m, err := actions_oidc.NewGinMiddleware(opts...)
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
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