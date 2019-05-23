package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"time"
)

// MaxIssueDelay is the longest allowed time between when a SAML assertion is
// issued by the IDP and the time it is received by ParseResponse. This is used
// to prevent old responses from being replayed (while allowing for some clock
// drift between the SP and IDP).
var MaxIssueDelay = time.Second * 300

// MaxClockSkew allows for leeway for clock skew between the IDP and SP when
// validating assertions. It defaults to 180 seconds (matches shibboleth).
var MaxClockSkew = time.Second * 180

// service implements a SAML service
type service struct {
	key                 *rsa.PrivateKey
	cert                *x509.Certificate
	samlIssuer          string
	defaultSAMLAudience string
}

// New returns a SAML service implementation
func New(keyPem []byte, certPem []byte, issuer string, defaultAudience string) (Interface, error) {
	// Decode key
	block, _ := pem.Decode(keyPem)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Decode cert
	block, _ = pem.Decode(certPem)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &service{key: key, cert: cert, samlIssuer: issuer, defaultSAMLAudience: defaultAudience}, nil
}

// GetSAMLResponse returns a SAML base64 encoded string
func (s service) GetSAMLResponse(ctx context.Context, audience, recipient, destination string, session Session, hasAttributeStatement bool) (string, error) {
	err := session.Validate()
	if err != nil {
		return "", err
	}

	responseID := fmt.Sprintf("response-%s", randomString(20))
	assertionID := fmt.Sprintf("assertion-%s", randomString(20))
	now := time.Now().Truncate(time.Second).UTC()
	until := now.Add(MaxIssueDelay).UTC()

	if audience == "" {
		audience = s.defaultSAMLAudience
	}

	//Assemble a AuthorizationResponse
	resp := Response{
		Version:      "2.0",
		IssueInstant: now,
		Destination:  destination,
		ID:           responseID,
		Assertion: Assertion{
			ID:           assertionID,
			Version:      "2.0",
			IssueInstant: now,
			Conditions: Conditions{
				AudienceRestriction: AudienceRestriction{
					Audience: audience,
				},
				NotBefore:    now.Add(-1 * MaxClockSkew),
				NotOnOrAfter: until,
			},
			Issuer: s.samlIssuer,
			AuthnStatement: AuthnStatement{
				AuthnInstant:        now,
				SessionIndex:        session.Index,
				SessionNotOnOrAfter: until,
				AuthnContext: AuthnContext{
					AuthnContextClassRef: AunthContextPasswordProtectedTransport,
				},
			},
			Subject: Subject{
				NameID: NameID{
					Format: NameFormatUnspecified,
					ID:     session.NameID,
				},
				Confirmation: SubjectConfirmation{
					Method: TokenTypeBearer,
					Data: SubjectConfirmationData{
						Recipient:    recipient,
						NotOnOrAfter: until,
					},
				},
			},
		},
		Issuer: Issuer{
			Format: NameIDFormatEntity,
			Issuer: s.samlIssuer,
		},
	}
	resp.SetSuccess()

	if hasAttributeStatement {
		resp.AddEmailAssertion(session.UserEmail)
		resp.AddUIDAssertion(session.NameID)
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

// ProcessSAMLRequest returns a AuthnRequest object from the SAML request string
func (s service) ProcessSAMLRequest(ctx context.Context, requestInput string) (*AuthnRequest, error) {
	if requestInput == "" {
		return nil, fmt.Errorf("requestInput cannot be empty")
	}

	res, err := processRequest(ctx, requestInput)
	if err != nil {
		return nil, err
	}

	return res, nil
}
