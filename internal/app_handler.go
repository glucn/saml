package internal

import (
	"context"
	"net/http"
	"time"
)

// StandardHTTPContextTimeout is a reasonable timeout to apply to the
// context on most HTTP requests.
const StandardHTTPContextTimeout = 30 * time.Second

// AppHandler handles an http handler function that returns an error
type AppHandler func(context.Context, http.ResponseWriter, *http.Request) error

// ServeHTTP introduces error handling for an http server
func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), StandardHTTPContextTimeout)
	defer cancel()
	if err := fn(ctx, w, r); err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
	}
}
