package sessionrepository

import (
	"time"
)

// User represents the user information of a session
type User struct {
	FirstName string
	LastName  string
	Email     string
	UserID    string
}

// Session represents a session
type Session struct {
	SessionID string
	PartnerID string
	User      *User
	IssuedAt  time.Time
	Expiry    time.Time
}
