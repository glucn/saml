package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"time"
)

// Interface for a saml service
type Interface interface {
	ProcessSAMLRequest(ctx context.Context, requestInput string) (*AuthnRequest, error)
	GetSAMLResponse(ctx context.Context, userID, sessionID, email, audience string, hasAttributeStatement bool) (string, error)
}

// Service implements a SAML service
type Service struct {
	key                 *rsa.PrivateKey
	cert                *x509.Certificate
	SAMLIssuer          string
	DefaultSAMLAudience string
}

// New returns a SAML service implementation
func New(keyPath, certPath, issuer, defaultAudience string) (Interface, error) {
	pemData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pemData, err = ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ = pem.Decode(pemData)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf(err.Error())
		return nil, err
	}

	return &Service{key: key, cert: cert, SAMLIssuer: issuer, DefaultSAMLAudience: defaultAudience}, nil
}

// GetSAMLResponse returns a SAML base64 encoded string
func (s *Service) GetSAMLResponse(ctx context.Context, userID, sessionID, email, audience string, hasAttributeStatement bool) (string, error) {
	err := validateParams(sessionID, email)
	if err != nil {
		return "", err
	}

	responseID := "response"
	assertionID := "assertion"
	now := time.Now().Add(-(time.Hour * 2)).Round(time.Second).UTC()
	until := now.Add(time.Hour * 2).Round(time.Second).UTC()

	if audience == "" {
		audience = s.DefaultSAMLAudience
	}

	//Assemble a AuthorizationResponse
	resp := Response{
		Version:      "2.0",
		IssueInstant: now,
		Destination:  audience,
		ID:           responseID,
		Assertion: Assertion{
			ID:           assertionID,
			Version:      "2.0",
			IssueInstant: now,
			Conditions: Conditions{
				AudienceRestriction: AudienceRestriction{
					Audience: audience,
				},
				NotBefore:    now.Add(-3 * time.Hour).UTC(),
				NotOnOrAfter: until,
			},
			Issuer: s.SAMLIssuer,
			AuthnStatement: AuthnStatement{
				AuthnInstant:        now,
				SessionIndex:        sessionID,
				SessionNotOnOrAfter: until,
				AuthnContext: AuthnContext{
					AuthnContextClassRef: AunthContextPasswordProtectedTransport,
				},
			},
			Subject: Subject{
				NameID: NameID{
					Format: NameFormatUnspecified,
					ID:     userID,
				},
				Confirmation: SubjectConfirmation{
					Method: TokenTypeBearer,
					Data: SubjectConfirmationData{
						Recipient:    audience,
						NotOnOrAfter: until,
					},
				},
			},
		},
		Issuer: Issuer{
			Format: NameIDFormatEntity,
			Issuer: s.SAMLIssuer,
		},
	}

	if resp.Assertion.AttributeStatement == nil {
		resp.Assertion.AttributeStatement = &AttributeStatement{}
	}
	resp.Assertion.AttributeStatement.Attributes = []Attribute{
		{
			Name:       "IDPEmail",
			NameFormat: NameFormatBasic,
			Values: []AttributeValue{
				{
					//TODO: setting Type value breaks MS SSO
					XMLNS: "http://www.w3.org/2001/XMLSchema",
					Value: email,
				},
			},
		},
	}

	resp.SetSuccess()

	if hasAttributeStatement {
		resp.AddEmailAssertion(email)
		resp.AddUIDAssertion(userID)
	}

	// Sign the AuthorizationResponse
	resp.Sign(*s.cert, *s.key, true)

	bytes, err := xml.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("unable to marshal XML")
	}
	bytes = append([]byte(xml.Header), bytes...)

	b64Data := base64.StdEncoding.EncodeToString(bytes)
	return b64Data, nil
}

func validateParams(sessionID, email string) error {
	if sessionID == "" {
		return fmt.Errorf("session_id must not be empty")
	}
	if email == "" {
		return fmt.Errorf("email must not be empty")
	}
	return nil
}

// ProcessSAMLRequest returns a AuthnRequest object from the SAML request string
func (s *Service) ProcessSAMLRequest(ctx context.Context, requestInput string) (*AuthnRequest, error) {
	if requestInput == "" {
		return nil, fmt.Errorf("requestInput cannot be empty")
	}

	res, err := processRequest(ctx, requestInput)
	if err != nil {
		return nil, err
	}

	return res, nil
}
