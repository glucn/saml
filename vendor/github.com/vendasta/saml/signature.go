package saml

import "encoding/xml"

// CanonicalizationMethod is the structure of the conocalization method
type CanonicalizationMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// SignatureMethod signature method
type SignatureMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// Transform xml transform structure
type Transform struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// DigestMethod method for digesting
type DigestMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// Reference xml reference
type Reference struct {
	XMLName      xml.Name     `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	Transforms   []Transform  `xml:"http://www.w3.org/2000/09/xmldsig# Transforms>Transform"`
	DigestMethod DigestMethod `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue  string       `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
	URI          string       `xml:"URI,attr"`
}

// SignedInfo is the signed information
type SignedInfo struct {
	XMLName                xml.Name               `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod CanonicalizationMethod `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	SignatureMethod        SignatureMethod        `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Reference              Reference              `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
}

// X509Data X509 data
type X509Data struct {
	XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate string   `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

// KeyInfo is the info for the key
type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data X509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

// Signature is the signature
type Signature struct {
	XMLName        xml.Name   `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     SignedInfo `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	SignatureValue string     `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	KeyInfo        KeyInfo    `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

//SignableElement Allows for XML Structures to support Signing
type SignableElement interface {
	GetID() string
	SetSignature(sig *Signature)
}
