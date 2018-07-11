package saml

import (
	"encoding/xml"
	"time"
)

// LogoutRequest is the request for logging out
type LogoutRequest struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr"`

	Issuer    string    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	NameID    NameID    `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
}

// LogoutResponse is the response for logging out
type LogoutResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`

	Issuer    string    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	Status    Status    `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}
