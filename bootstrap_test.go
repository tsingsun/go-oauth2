package oauth2_test

import (
	"github.com/tsingsun/go-oauth2"
	"time"
)

var (
	defaultService *oauth2.Service
)

const (
	ENCRYPTION_KEY = "cxPrjjamV6wI82ka"
)

type Client struct {
	oauth2.ClientEntity
}

type ClientRepository struct {
	oauth2.ClientRepositoryInterface
	Db string
}

func (c *ClientRepository) GetClientEntity(clientIdentifier string, grantType oauth2.GrantType, clientSecret string, mustValidateSecret bool) oauth2.ClientEntityInterface {
	cl := &Client{
		ClientEntity: oauth2.ClientEntity{
			Entity: oauth2.Entity{
				Identifier: "user01",
			},
			Name:        "name01",
			RedirectUri: []string{"http://localhost"},
		},
	}
	return cl
}

type AccessToken struct {
	oauth2.AccessTokenEntity
}

type AccessTokenRepository struct {
	oauth2.AccessTokenRepositoryInterface
}

func (a *AccessTokenRepository) GetNewToken(ce oauth2.ClientEntityInterface, scopes []oauth2.ScopeEntityInterface, userIdentifier string) oauth2.AccessTokenEntityInterface {
	at := &AccessToken{}
	at.SetClient(ce)
	for _, v := range scopes {
		at.AddScope(v)
	}
	return at
}

func (a *AccessTokenRepository) PersistNewAccessToken(accessTokenEntity oauth2.AccessTokenEntityInterface) bool {
	return true
}

func (a *AccessTokenRepository) RevokeAccessToken(tokenId string) {

}

func (a *AccessTokenRepository) IsAccessTokenRevoked(tokenId string) bool {
	return true
}

type Scope struct {
	oauth2.Entity
	oauth2.ScopeEntityInterface
}

type ScopeRepository struct {
	oauth2.ScopeRepositoryInterface
}

func (s *Scope) getIdentifier() string {
	return s.Identifier
}

func (s *ScopeRepository) GetScopeEntityByIdentifier(identifier string) oauth2.ScopeEntityInterface {
	sps := make(map[string]string)
	sps["basic"] = "basic info"
	sps["social"] = "get info"
	return &Scope{}
}

func (s *ScopeRepository) FinalizeScopes(scopes []oauth2.ScopeEntityInterface, grantType oauth2.GrantType, clientEntity oauth2.ClientEntityInterface) []oauth2.ScopeEntityInterface {
	return []oauth2.ScopeEntityInterface{&Scope{}}
}

type RefreshToken struct {
	oauth2.RefreshTokenEntity
}

type RefreshTokenRepository struct {
	oauth2.RefreshTokenRepositoryInterface
}

func (t *RefreshTokenRepository) GetNewRefreshToken() oauth2.RefreshTokenEntityInterface {
	return &RefreshToken{}
}

// Create a new refresh token_name.
func (t *RefreshTokenRepository) PersistNewRefreshToken(refreshTokenEntity oauth2.RefreshTokenEntityInterface) bool {
	return true
}

// Revoke the refresh token.
func (t *RefreshTokenRepository) RevokeRefreshToken(tokenId string) {

}

// Check if the refresh token has been revoked.
func (t *RefreshTokenRepository) IsRefreshTokenRevoked(tokenId string) bool {
	return true
}

type User struct {
	oauth2.UserEntityInterface
	oauth2.UserRepositoryInterface
}

func (u *User) GetIdentifier() string {
	// must return web site current user
	return "0001"
}

func (u *User) GetUserEntityByUserCredentials(username string, password string, grantType string, clientEntity oauth2.ClientEntityInterface) oauth2.UserEntityInterface {
	return new(User)
}

type AuthCode struct {
	oauth2.AuthCodeEntity
}

func init() {

	defaultService = oauth2.NewService(
		oauth2.SetClientRepository(&ClientRepository{}),
		oauth2.SetAccessTokenRepository(&AccessTokenRepository{}),
		oauth2.SetResponseType(&oauth2.BearerTokenResponse{}),
		oauth2.SetScopeRepository(&ScopeRepository{}),
		oauth2.SetEncryptionKey("abcd"),
	)
	accessTokenTTL := 7200 * time.Second
	grant1 := oauth2.NewClientCredentialsGrant(defaultService.Options())
	grant1.SetAccessTokenTTL(accessTokenTTL)
	defaultService.RegisterGrantType(grant1)
}
