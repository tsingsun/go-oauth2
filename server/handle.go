package server

import (
	"github.com/tsingsun/go-oauth2/errors"
	"net/http"
)

// ClientBasicHandler get client data from basic authorization ,header like : Authorization: Basic ZGVtbzpwQDU1dzByZA==
func getBasicAuthCredentialsHandle(r *http.Request) (clientID, clientSecret string, err error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		err = errors.ErrInvalidClient
		return
	}
	clientID = username
	clientSecret = password
	return
}
