package saml

import (
	"encoding/xml"
)

const (
	// ProtocolBindingSOAP is the binding for SOAP
	ProtocolBindingSOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
	// ProtocolBindingPAOS is the binding for PAOS
	ProtocolBindingPAOS = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"
	// ProtocolBindingHTTPRedirect is the binding for HTTP Redirect
	ProtocolBindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	// ProtocolBindingHTTPPost is the binding for HTTP post
	ProtocolBindingHTTPPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	// ProtocolBindingHTTPArtifact is the binding for HTTP Artifact
	ProtocolBindingHTTPArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
)

// NameIDPolicy is the name id policy
type NameIDPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format      string   `xml:"Format,attr"`
	AllowCreate bool     `xml:"AllowCreate,attr"`
}

// RequestedAuthnContext is the request authentication context
type RequestedAuthnContext struct {
	XMLName              xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`
	Comparison           string   `xml:"Comparison,attr"`
	AuthnContextClassRef string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
}
