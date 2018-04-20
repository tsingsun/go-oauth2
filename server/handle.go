package server

import (
	"github.com/tsingsun/go-oauth2/errors"
	"net/http"
)

// ClientFormHandler get client data from form
func ClientFormHandler(r *http.Request) (clientID, clientSecret string, err error) {
	clientID = r.Form.Get("client_id")
	clientSecret = r.Form.Get("client_secret")
	if clientID == "" || clientSecret == "" {
		err = errors.NewInvalidClient()
	}
	return
}

// ClientBasicHandler get client data from basic authorization ,header like : Authorization: Basic ZGVtbzpwQDU1dzByZA==
func getBasicAuthCredentialsHandle(r *http.Request) (clientID, clientSecret string, err error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		err = errors.NewInvalidClient()
		return
	}
	clientID = username
	clientSecret = password
	return
}
