package models

import "github.com/tsingsun/go-oauth2"

type AccessToken struct {
	oauth2.AccessTokenRepositoryInterface
	oauth2.AccessTokenEntity
}

func (a *AccessToken) GetNewToken(ce oauth2.ClientEntityInterface, scopes []oauth2.ScopeEntityInterface, userIdentifier string) oauth2.AccessTokenEntityInterface {
	at := &AccessToken{}
	at.SetClient(ce)
	for _, v := range scopes {
		at.AddScope(v)
	}
	return at
}

func (a *AccessToken) PersistNewAccessToken(accessTokenEntity oauth2.AccessTokenEntityInterface) bool {
	return true
}

func (a *AccessToken) RevokeAccessToken(tokenId string) {

}

func (a *AccessToken) IsAccessTokenRevoked(tokenId string) bool {
	return true
}
