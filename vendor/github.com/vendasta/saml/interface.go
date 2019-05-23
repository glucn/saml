package saml

import "context"

// Interface for a saml service
type Interface interface {
	ProcessSAMLRequest(ctx context.Context, requestInput string) (*AuthnRequest, error)
	GetSAMLResponse(ctx context.Context, audience, recipient, destination string, session Session, hasAttributeStatement bool) (string, error)
}
