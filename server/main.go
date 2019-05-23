package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/glucn/saml/internal/api"
	"github.com/vendasta/saml"
)

func main() {
	var err error

	keyPath := "keys/test2/rsaprivkey.pem"
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		panic(err.Error())
	}

	certPath := "keys/test2/rsacert.pem"
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		panic(err.Error())
	}

	samlService, err := saml.New(key, cert,
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
