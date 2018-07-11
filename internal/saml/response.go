package saml

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"time"

	"fknsrs.biz/p/xml/c14n"
)

const (
	// AuthnContextPassword means the user logged in with a username and password over HTTP
	AuthnContextPassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"

	// AunthContextPasswordProtectedTransport means the user logged in with a username and password over HTTPS
	AunthContextPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

	// AuthnContextTLSClient means the user logged in with a TLS Client Cert
	AuthnContextTLSClient = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"

	// AuthnContextMobileTwoFactorUnregistered means mobile 2-factor (ie. Device + fingerprint)
	AuthnContextMobileTwoFactorUnregistered = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered"

	// AuthnContextMobileTwoFactorContract means 2-factor with a tamper resistance (ie. Device + yubikey)
	AuthnContextMobileTwoFactorContract = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"

	// AttributeUserID the user id
	AttributeUserID = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
	// AttributeEmail the email
	AttributeEmail = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"

	// NameFormatBasic basic name format
	NameFormatBasic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	// NameFormatURI uri format
	NameFormatURI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	// NameIDFormatEntity entity format
	NameIDFormatEntity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	// NameFormatUnspecified unspecified format
	NameFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"

	// XMLString an xml string
	XMLString = "xs:string"

	// TokenTypeBearer is a bearer token type
	TokenTypeBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	// NameIDFormatTransient transient format
	NameIDFormatTransient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

	// AlgorithmCanonicalizationExclusive Canonicalization exclusive
	AlgorithmCanonicalizationExclusive = "http://www.w3.org/2001/10/xml-exc-c14n#"
	// AlgorithmSignatureRSASHA1 signature RSASHA1
	AlgorithmSignatureRSASHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	// AlgorithmDigestSHA1 digest SHA1
	AlgorithmDigestSHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
	// AlgorithmXMLSignature XML signature
	AlgorithmXMLSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// NameID xml structure
type NameID struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SPNameQualifier string   `xml:"SPNameQualifier,attr,omitempty"`
	Format          string   `xml:"Format,attr"`
	ID              string   `xml:",chardata"`
}

// SubjectConfirmationData is the confirmation data structure
type SubjectConfirmationData struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
	Recipient    string    `xml:"Recipient,attr"`
	InResponseTo string    `xml:"InResponseTo,attr,omitempty"`
}

// SubjectConfirmation is the subject comfirmation
type SubjectConfirmation struct {
	XMLName xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
	Method  string                  `xml:"Method,attr"`
	Data    SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

// Subject is a subject
type Subject struct {
	XMLName      xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID       NameID              `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Confirmation SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

// AudienceRestriction are any audience restrictions
type AudienceRestriction struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	Audience string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

// Conditions is the conditions
type Conditions struct {
	XMLName             xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	NotBefore           time.Time           `xml:"NotBefore,attr"`
	NotOnOrAfter        time.Time           `xml:"NotOnOrAfter,attr"`
	AudienceRestriction AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

// AuthnContext is the authentication context
type AuthnContext struct {
	XMLName              xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
	AuthnContextClassRef string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
}

// AuthnStatement is the authentication statement
type AuthnStatement struct {
	XMLName             xml.Name     `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AuthnInstant        time.Time    `xml:"AuthnInstant,attr"`
	SessionNotOnOrAfter time.Time    `xml:"SessionNotOnOrAfter,attr"`
	SessionIndex        string       `xml:"SessionIndex,attr"`
	AuthnContext        AuthnContext `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
}

// AttributeValue is an attribute value
type AttributeValue struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	XMLNS   string   `xml:"xmlns:xs,attr"`
	Type    string   `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value   string   `xml:",chardata"`
}

// Attribute is an attribute
type Attribute struct {
	XMLName    xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	Name       string           `xml:"Name,attr"`
	NameFormat string           `xml:"NameFormat,attr"`
	Values     []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

// AttributeStatement is an attribute statement
type AttributeStatement struct {
	XMLName    xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// Assertion is a saml assertion
type Assertion struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`

	Issuer             string              `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature          *Signature          `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	Subject            Subject             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions         Conditions          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AuthnStatement     AuthnStatement      `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AttributeStatement *AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement,omitempty"`
}

// GetID returns an assertion ID
func (a *Assertion) GetID() string {
	return a.ID
}

// SetSignature sets an assertion signature
func (a *Assertion) SetSignature(sig *Signature) {
	a.Signature = sig
}

// Issuer is an issuer
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Format  string   `xml:"Format,attr"`
	Issuer  string   `xml:",chardata"`
}

// Response is the SAML response
type Response struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr,omitempty"`
	InResponseTo string    `xml:"InResponseTo,attr,omitempty"`

	Issuer    Issuer     `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature *Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	Status    Status     `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion Assertion  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// GetID returns the response ID
func (resp *Response) GetID() string {
	return resp.ID
}

// SetSignature sets the response signature
func (resp *Response) SetSignature(sig *Signature) {
	resp.Signature = sig
}

// AddUIDAssertion adds a user id assertion
func (resp *Response) AddUIDAssertion(userID string) {
	if resp.Assertion.AttributeStatement == nil {
		resp.Assertion.AttributeStatement = &AttributeStatement{}
	}
	resp.Assertion.AttributeStatement.Attributes = append(
		resp.Assertion.AttributeStatement.Attributes,
		Attribute{
			Name:       AttributeUserID,
			NameFormat: NameFormatBasic,
			Values: []AttributeValue{
				AttributeValue{
					Type:  XMLString,
					XMLNS: "http://www.w3.org/2001/XMLSchema",
					Value: userID,
				},
			},
		})
}

// AddEmailAssertion adds an email to an assertion
func (resp *Response) AddEmailAssertion(email string) {
	if resp.Assertion.AttributeStatement == nil {
		resp.Assertion.AttributeStatement = &AttributeStatement{}
	}
	resp.Assertion.AttributeStatement.Attributes = append(
		resp.Assertion.AttributeStatement.Attributes,
		Attribute{
			Name:       AttributeEmail,
			NameFormat: NameFormatBasic,
			Values: []AttributeValue{
				AttributeValue{
					Type:  XMLString,
					XMLNS: "http://www.w3.org/2001/XMLSchema",
					Value: email,
				},
			},
		})
}

func sign(cert x509.Certificate, key rsa.PrivateKey, element SignableElement) error {
	//Serialize the message (without signature)
	element.SetSignature(nil)
	messageBytes, err := xml.Marshal(element)
	if err != nil {
		return err
	}

	//Set the Algorithms
	sig := &Signature{}

	sig.SignedInfo.CanonicalizationMethod.Algorithm = AlgorithmCanonicalizationExclusive
	sig.SignedInfo.SignatureMethod.Algorithm = AlgorithmSignatureRSASHA1
	sig.SignedInfo.Reference.DigestMethod.Algorithm = AlgorithmDigestSHA1
	sig.SignedInfo.Reference.Transforms = []Transform{
		Transform{Algorithm: AlgorithmXMLSignature},
		Transform{Algorithm: AlgorithmCanonicalizationExclusive},
	}
	sig.SignedInfo.Reference.URI = fmt.Sprintf("#%s", element.GetID())

	//Canonicalize the XML message
	inputBuffer := bytes.NewBuffer(messageBytes)
	outputBuffer := bytes.NewBufferString("")
	outputBufferWrapper := NewNopWriteCloser(outputBuffer)
	decoder := xml.NewDecoder(inputBuffer)
	err = c14n.Canonicalise(decoder, outputBufferWrapper, false)
	if err != nil {
		return err
	}

	//Hash the canonicalized message to form a digest
	sum := sha1.Sum(outputBuffer.Bytes())
	digest := base64.StdEncoding.EncodeToString(sum[:])
	sig.SignedInfo.Reference.DigestValue = digest

	messageBytes, err = xml.Marshal(sig.SignedInfo)
	if err != nil {
		return err
	}

	//Canonicalize the XML message
	inputBuffer = bytes.NewBuffer(messageBytes)
	outputBuffer = bytes.NewBufferString("")
	outputBufferWrapper = NewNopWriteCloser(outputBuffer)
	decoder = xml.NewDecoder(inputBuffer)
	err = c14n.Canonicalise(decoder, outputBufferWrapper, false)
	if err != nil {
		return err
	}

	//Hash the canonicalized message to form a digest
	sum = sha1.Sum(outputBuffer.Bytes())

	//Generate a signature
	signature, err := key.Sign(rand.Reader, []byte(sum[:]), crypto.SHA1)
	if err != nil {
		return err
	}
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	sig.SignatureValue = encodedSignature

	//Add the cert
	sig.KeyInfo.X509Data.X509Certificate = base64.StdEncoding.EncodeToString(cert.Raw)
	element.SetSignature(sig)

	return nil
}

// Sign a response
func (resp *Response) Sign(cert x509.Certificate, key rsa.PrivateKey, signAssertion bool) {
	var err error
	//Sign assertion first, if requested
	if signAssertion {
		err = sign(cert, key, &resp.Assertion)
		if err != nil {
			fmt.Printf("Error signing Assertion: %s\n", err.Error())
		}
	}
	err = sign(cert, key, resp)
	if err != nil {
		fmt.Printf("Error signing Response: %s\n", err.Error())
	}
}

// SetSuccess is a helper to just responding with success
func (resp *Response) SetSuccess() {
	resp.Status = Status{
		StatusCode: StatusCode{
			Value: StatusSuccess,
		},
	}
}
