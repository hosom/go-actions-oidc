package main

import (
	"net/http"
	"os"

	"github.com/hosom/actions_oidc"
)

func main() {
	// Example usage of the actions_oidc package
	aud := "example-audience"
	token, err := actions_oidc.RequestToken(aud)
	if err != nil {
		panic(err)
	}
	println("Token:", token)

	// use the returned token
	client := http.DefaultClient
	req, err := http.NewRequest(http.MethodGet, os.Getenv("TEST_URL"), nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic("failed to fetch resource")
	}

}
