package saml

import "context"

// Interface for a saml service
type Interface interface {
	ProcessSAMLRequest(ctx context.Context, requestInput string) (*AuthnRequest, error)
	GetSAMLResponse(ctx context.Context, userID, sessionID, email, audience, recipient, destination string, hasAttributeStatement bool) (string, error)
}
