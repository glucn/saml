package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/glucn/saml/internal/api"
	"github.com/glucn/saml/internal/saml"
)

func main() {
	var err error

	samlService, err := saml.New(
		"/Users/glu/go/src/github.com/vendasta/constant-contact/saml-keys/demo/saml.key",
		"/Users/glu/go/src/github.com/vendasta/constant-contact/saml-keys/demo/saml.crt",
		"vendasta",
		"https://idfed.constantcontact.com/sp/ACS.saml2",
	)
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
