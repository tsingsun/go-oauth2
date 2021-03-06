package models

import (
	"context"
	"github.com/tsingsun/go-oauth2"
)

type AccessToken struct {
	oauth2.AccessTokenRepositoryInterface
	oauth2.AccessTokenEntity
}

func (a *AccessToken) GetNewToken(ctx context.Context,ce oauth2.ClientEntityInterface, scopes []oauth2.ScopeEntityInterface, userIdentifier string) oauth2.AccessTokenEntityInterface {
	at := &AccessToken{}
	at.SetClient(ce)
	for _, v := range scopes {
		at.AddScope(v)
	}
	return at
}

func (a *AccessToken) PersistNewAccessToken(ctx context.Context,accessTokenEntity oauth2.AccessTokenEntityInterface) bool {
	return true
}

func (a *AccessToken) RevokeAccessToken(ctx context.Context,tokenId string) {

}

func (a *AccessToken) IsAccessTokenRevoked(ctx context.Context,tokenId string) bool {
	return true
}
