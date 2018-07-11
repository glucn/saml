package main

import (
	"fmt"
	"github.com/glucn/saml/internal/api"
	"github.com/glucn/saml/internal/saml"
	"log"
	"net/http"
	"os"
)

func main() {
	var err error

	samlService, err := saml.New("keys/test2/rsaprivkey.pem", "keys/test2/rsacert.pem",
		"https://www.google.com/a/socialconnections.com/acs", "https://www.google.com/a/socialconnections.com/acs")
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
