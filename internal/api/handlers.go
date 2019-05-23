package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/glucn/saml/internal/session/repository"
	"github.com/vendasta/saml"
)

const (
	ssoLogin = "https://www.google.com/a/socialconnections.com/acs"
)

// HTTPServer is the http server implementation
type HTTPServer struct {
	saml saml.Interface
}

// NewHTTPServer returns a new implementation of the http server
func NewHTTPServer(samlService saml.Interface) Server {
	return &HTTPServer{
		saml: samlService,
	}
}

func (h *HTTPServer) SignIn(w http.ResponseWriter, r *http.Request) {
	// process the request
	var authnRequest *saml.AuthnRequest
	var err error
	var relayState string
	switch r.Method {
	case "GET":
		fmt.Printf("GET: %s\n", r.URL)
		authnRequest, err = h.saml.ProcessSAMLRequest(context.Background(), r.URL.Query().Get("SAMLRequest"))
		if err != nil {
			fmt.Printf("Error in ProcessSAMLRequest: %s", err.Error())
		}
		relayState = r.URL.Query().Get("RelayState")

		break
	case "POST":
		fmt.Printf("POST\n")
		fmt.Printf("mothod not implemented")
		break
	default:
		fmt.Printf("method not allowed")
		return
	}
	fmt.Fprintf(w, "<h1>Sign In</h1><div>authnRequest: %v</div><div>relayState: %s</div>", *authnRequest, relayState)

	// TODO: authenticate user - check session or redirect to VBC login
	var session *sessionrepository.Session

	session = &sessionrepository.Session{
		User: &sessionrepository.User{
			Email:  "developers@socialconnections.com",
			UserID: "developers",
		},
		SessionID: "sessionID",
	}

	// build response and redirect to relayState  TODO: add relayState to the page
	h.buildSAMLPage(context.Background(), w, session)
}

func (h *HTTPServer) Entry(w http.ResponseWriter, r *http.Request) {
	// TODO: authenticate user - check session or redirect to VBC login
	var session *sessionrepository.Session
	session = &sessionrepository.Session{
		User: &sessionrepository.User{
			Email:  "developers@socialconnections.com",
			UserID: "developers",
		},
		SessionID: "sessionID",
	}

	// build response and redirect
	h.buildSAMLPage(context.Background(), w, session)
}

func (h *HTTPServer) buildSAMLPage(ctx context.Context, w http.ResponseWriter, session *sessionrepository.Session) error {
	var samlResp string
	var err error

	fmt.Printf("Session: %+v\n", session)

	audience := "https://www.google.com/a/goog-test.demosso.com.reseller.vendasta.com/acs"

	samlSess := saml.Session{
		UserEmail: "admin@goog-test.demosso.com.reseller.vendasta.com",
		Index:     "randomsessionid",
		NameID:    "admin@goog-test.demosso.com.reseller.vendasta.com",
	}

	//if session == nil {
	samlResp, err = h.saml.GetSAMLResponse(ctx, audience, audience, audience, samlSess, false)
	//} else {
	//	fmt.Printf("UserID: %s\n", session.User.UserID)
	//	fmt.Printf("SessionID: %s\n", session.SessionID)
	//	fmt.Printf("Email: %s\n", session.User.Email)
	//	samlResp, err = h.saml.GetSAMLResponse(ctx, session.User.UserID, session.SessionID, session.User.Email, audience, audience, audience, false)
	//}

	if err != nil {
		fmt.Printf("Error in GetSAMLResponse: %s", err.Error())
		return fmt.Errorf("internal error")
	}

	fmt.Println(samlResp)
	fmt.Fprintf(w, samlPage, audience, samlResp,
		"https://apps.google.com/user/hub")
	return nil
}

var samlPage = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <title>POST data</title>
</head>
<body onload="document.getElementsByTagName('input')[0].click();">
    <noscript>
        <p><strong>Note:</strong> Since your browser does not support JavaScript, you must
            press the button below once to proceed.</p>
    </noscript>
    <form method="post" action="%s">
        <input type="submit" style="display:none;" />
        <input type="hidden" name="SAMLResponse" value="%s" />
		<input type="hidden" name="RelayState" value="%s" />
        <noscript>
            <input type="submit" value="Submit" />
        </noscript>
    </form>
</body>
</html>`
