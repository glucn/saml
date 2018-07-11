package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"time"
)

// AuthnRequest is the authentication request
type AuthnRequest struct {
	XMLName                     xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string    `xml:"ID,attr"`
	Version                     float64   `xml:"Version,attr"`
	ProviderName                string    `xml:"ProviderName,attr"`
	IssueInstant                time.Time `xml:"IssueInstant,attr"`
	Destination                 string    `xml:"Destination,attr"`
	ProtocolBinding             string    `xml:"ProtocolBinding,attr"`
	AssertionConsumerServiceURL string    `xml:"AssertionConsumerServiceURL,attr"`
	IsPassive                   bool      `xml:"IsPassive,attr"`

	Issuer                string                `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy          NameIDPolicy          `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	RequestedAuthnContext RequestedAuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`

	Signature Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
}

func processRequest(ctx context.Context, requestString string) (*AuthnRequest, error) {
	// decode from base64
	compressedRequest, err := base64.StdEncoding.DecodeString(requestString)
	if err != nil {
		return nil, err
	}

	// inflate
	inflatedRequest, err := ioutil.ReadAll(flate.NewReader(bytes.NewReader(compressedRequest)))
	if err != nil {
		return nil, fmt.Errorf("cannot decompress request: %s", err)
	}

	// unmarshal XML
	var request AuthnRequest
	err = xml.Unmarshal(inflatedRequest, &request)
	if err != nil {
		return nil, err
	}

	// validate the request
	err = validate(&request)
	if err != nil {
		return nil, err
	}

	return &request, nil
}

func validate(req *AuthnRequest) error {
	// TODO: add valid validation here

	return nil
}
