package saml

import (
	"encoding/xml"
	"io"
	"time"
)

// ArtifactResolve resolves the artifact
type ArtifactResolve struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResolve"`
	ID           string    `xml:"ID,attr"`
	Version      float64   `xml:"Version,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr"`

	Issuer    string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature string `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	Artifact  string `xml:"urn:oasis:names:tc:SAML:2.0:protocol Artifact"`
}

const (
	// StatusSuccess is the status for success
	StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	// StatusRequestorFailure is the status for requestor failure
	StatusRequestorFailure = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	// StatusResponderFailure is the status for responder failure
	StatusResponderFailure = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	// StatusVersionFailure is the status for version failure
	StatusVersionFailure = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
)

// StatusCode XML structure
type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:"Value,attr"`
}

// Status xml structure
type Status struct {
	XMLName    xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

// ArtifactResponse XML structure
type ArtifactResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResponse"`
	ID           string    `xml:"ID,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`
	Version      float64   `xml:"Version,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`

	Signature Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	Status    Status    `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Response  string    `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
}

//NopWriteCloser implements an io.WriteCloser with a nop for a Closer
type NopWriteCloser struct {
	writer io.Writer
}

//NewNopWriteCloser creates a new instance from an existing io.Writer
func NewNopWriteCloser(w io.Writer) *NopWriteCloser {
	return &NopWriteCloser{writer: w}
}

//Write implements io.Writer
func (nwc *NopWriteCloser) Write(p []byte) (n int, err error) {
	return nwc.writer.Write(p)
}

//Close implements io.Closer (nop)
func (nwc *NopWriteCloser) Close() error {
	return nil
}
