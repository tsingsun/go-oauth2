package oauth2_test

import (
	"context"
	"github.com/tsingsun/go-oauth2"
	"io/ioutil"
	"time"
)

var (
	defaultService *oauth2.Service
)

const (
	ENCRYPTION_KEY = "cxPrjjamV6wI82ka"
	PRIVATE_KEY    = "./_example/rsa_auth_pkcs8.pem"
)

type Client struct {
	oauth2.ClientEntity
}

type ClientRepository struct {
	oauth2.ClientRepositoryInterface
	Db string
}

func (c *ClientRepository) GetClientEntity(ctx context.Context,clientIdentifier string, grantType oauth2.GrantType, clientSecret string, mustValidateSecret bool) oauth2.ClientEntityInterface {
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

func (a *AccessTokenRepository) GetNewToken(ctx context.Context,ce oauth2.ClientEntityInterface, scopes []oauth2.ScopeEntityInterface, userIdentifier string) oauth2.AccessTokenEntityInterface {
	at := &AccessToken{}
	at.SetClient(ce)
	for _, v := range scopes {
		at.AddScope(v)
	}
	return at
}

func (a *AccessTokenRepository) PersistNewAccessToken(ctx context.Context,accessTokenEntity oauth2.AccessTokenEntityInterface) bool {
	return true
}

func (a *AccessTokenRepository) RevokeAccessToken(ctx context.Context,tokenId string) {

}

func (a *AccessTokenRepository) IsAccessTokenRevoked(ctx context.Context,tokenId string) bool {
	return true
}

type Scope struct {
	oauth2.Entity
}

type ScopeRepository struct {
	oauth2.ScopeRepositoryInterface
}

func (s *ScopeRepository) GetScopeEntityByIdentifier(ctx context.Context,identifier string) oauth2.ScopeEntityInterface {
	sps := make(map[string]string)
	sps["basic"] = "basic info"
	sps["social"] = "get info"
	return &Scope{}
}

func (s *ScopeRepository) FinalizeScopes(ctx context.Context,scopes []oauth2.ScopeEntityInterface, grantType oauth2.GrantType, clientEntity oauth2.ClientEntityInterface) []oauth2.ScopeEntityInterface {
	return []oauth2.ScopeEntityInterface{&Scope{}}
}

type RefreshToken struct {
	oauth2.RefreshTokenEntity
}

type RefreshTokenRepository struct {
	oauth2.RefreshTokenRepositoryInterface
}

func (t *RefreshTokenRepository) GetNewRefreshToken(ctx context.Context) oauth2.RefreshTokenEntityInterface {
	return &RefreshToken{}
}

// Create a new refresh token_name.
func (t *RefreshTokenRepository) PersistNewRefreshToken(ctx context.Context,refreshTokenEntity oauth2.RefreshTokenEntityInterface) bool {
	return true
}

// Revoke the refresh token.
func (t *RefreshTokenRepository) RevokeRefreshToken(ctx context.Context,tokenId string) {

}

// Check if the refresh token has been revoked.
func (t *RefreshTokenRepository) IsRefreshTokenRevoked(ctx context.Context,tokenId string) bool {
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

func (u *User) GetUserEntityByUserCredentials(ctx context.Context,username string, password string, grantType string, clientEntity oauth2.ClientEntityInterface) oauth2.UserEntityInterface {
	return new(User)
}

type AuthCode struct {
	oauth2.AuthCodeEntity
}

func init() {
	c,_ := ioutil.ReadFile(PRIVATE_KEY)
	defaultService = oauth2.NewService(
		oauth2.WithClientRepository(&ClientRepository{}),
		oauth2.WithAccessTokenRepository(&AccessTokenRepository{}),
		oauth2.WithResponseType(&oauth2.BearerTokenResponse{}),
		oauth2.WithScopeRepository(&ScopeRepository{}),
		oauth2.WithEncryptionKey("abcdefgh"),
		oauth2.WithPrivateKey(c),
	)
	accessTokenTTL := 7200 * time.Second
	grant1 := oauth2.NewClientCredentialsGrant(defaultService.Options())
	grant1.SetAccessTokenTTL(accessTokenTTL)
	defaultService.RegisterGrantType(grant1)
}
