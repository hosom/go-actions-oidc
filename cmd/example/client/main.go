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
