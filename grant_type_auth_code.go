package oauth2

import (
	"github.com/tsingsun/go-oauth2/errors"
)

type AuthCodeGrant struct {
	Grant
	authCodeRepository     AuthCodeRepositoryInterface
	refreshTokenRepository RefreshTokenRepositoryInterface
	authCodeTTL            int
	encryptionKey          string
}

func NewAuthCodeGrant(options Options) *AuthCodeGrant {
	return &AuthCodeGrant{
		authCodeTTL:            3600,
		authCodeRepository:     options.AuthCodeRepository,
		refreshTokenRepository: options.RefreshTokenRepository,
		encryptionKey:          options.EncryptionKey,
	}
}

func (a *AuthCodeGrant) GetIdentifier() GrantType {
	return AuthCodeGrantType
}

func (a *AuthCodeGrant) SetRefreshTokenTTL(duration int) {
	a.authCodeTTL = duration
}

func (a *AuthCodeGrant) RespondAccessTokenRequest(cr TokenRequest, duration int) (res AccessTokenResponse, err error) {
	client, e := a.validateClient(cr)
	if e != nil {
		err = e
		return
	}
	if cr.Code == "" {
		err = errors.NewInvalidRequest("code", "")
		return
	}

	if e != nil {
		err = errors.NewInvalidRequest("code", "")
	}

	if a.authCodeRepository.IsAuthCodeExpired(cr.Code) {
		err = errors.NewInvalidRequest("code", "Authorization code has expired")
	}
	res = AccessTokenResponse{
		UserID: client.GetIdentifier(),
	}
	return
}
