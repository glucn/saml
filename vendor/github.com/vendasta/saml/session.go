package saml

import (
	"fmt"
	"time"
)

// Session represents a user session.
type Session struct {
	ID         string
	CreateTime time.Time
	ExpireTime time.Time
	Index      string

	NameID         string
	Groups         []string
	UserName       string
	UserEmail      string
	UserCommonName string
	UserSurname    string
	UserGivenName  string
}

func (s Session) Validate() error {
	if s.Index == "" {
		return fmt.Errorf("index of a session must not be empty")
	}
	if s.NameID == "" {
		return fmt.Errorf("nameID of a session must not be empty")
	}
	return nil
}
