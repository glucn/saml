package api

import (
	"net/http"
)

// Server is the interface of an http server
type Server interface {
	SignIn(w http.ResponseWriter, r *http.Request)
	Entry(w http.ResponseWriter, r *http.Request)
	Reset(w http.ResponseWriter, r *http.Request)
}
