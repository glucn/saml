package main

import (
	"fmt"
	"github.com/vendasta/saml/internal/api"
	"github.com/vendasta/saml/internal/saml"
	"log"
	"net/http"
	"os"
)

func main() {
	var err error

	samlService, err := saml.New("keys/rsaprivkey.pem", "keys/rsacert.pem",
		"https://ExampleIdentityProvider", "urn:federation:MicrosoftOnline")
	if err != nil {
		fmt.Printf("Error starting saml service\n")
		os.Exit(-1)
	}

	fmt.Printf("Starting HTTP server...\n")
	httpServer := api.NewHTTPServer(
		samlService,
	)
	http.HandleFunc("/signin/", httpServer.SignIn) // SP initiate
	http.HandleFunc("/entry/", httpServer.Entry)   // IdP initiate
	http.HandleFunc("/reset-password/", httpServer.Reset)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
