package actions_oidc

import (
	"context"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	GitHubWellKnownURL = "https://token.actions.githubusercontent.com/.well-known/jwks"
)

func main() {

	ctx := context.Background()
	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return
	}

	if err := cache.Register(ctx, GitHubWellKnownURL); err != nil {
		return
	}

	keyset, err := cache.Lookup(ctx, GitHubWellKnownURL)
	if err != nil {
		return
	}

	_ = keyset

	token := []byte(`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`)
	parsed, err := jwt.Parse(token, jwt.WithKeySet(keyset))
	if err != nil {
		return
	}

	// Do something with the parsed token
	_ = parsed
}
