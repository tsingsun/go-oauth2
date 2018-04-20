package oauth2

import (
	OauthErrors "github.com/tsingsun/go-oauth2/errors"
)

type TokenRequest struct {
	// access_token
	GrantType    GrantType
	ClientId     string
	ClientSecret string
	// AuthorizationCode
	RedirectUri string
	Code        string
	// PasswordCredentials
	Scope        string
	Username     string
	Password     string
	RefreshToken string
}

func (t TokenRequest) Validate() error {
	if t.GrantType == "" {
		return OauthErrors.NewInvalidGrant()
	}

	switch t.GrantType {
	case AuthCodeGrantType:
		if t.RedirectUri == "" || t.Code == "" {
			return OauthErrors.NewInvalidRequest("code,redirect_uri", "")
		}
	case PasswordGrantType:
		if t.Username == "" || t.Password == "" {
			return OauthErrors.NewInvalidRequest("username,password", "")
		}
	case RefreshTokenGrantType:
		if t.RefreshToken == "" {
			return OauthErrors.NewInvalidRequest("refresh_token", "")
		}
	}
	return nil
}
