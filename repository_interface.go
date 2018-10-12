package oauth2

import "context"

// Access token interface.
type AccessTokenRepositoryInterface interface {
	// Create a new access token
	GetNewToken(ctx context.Context,ce ClientEntityInterface, scopes []ScopeEntityInterface, userIdentifier string) AccessTokenEntityInterface
	// Persists a new access token to permanent storage.
	PersistNewAccessToken(ctx context.Context,accessTokenEntity AccessTokenEntityInterface) bool
	// Revoke an access token.
	RevokeAccessToken(ctx context.Context,tokenId string)
	// Check if the access token has been revoked.
	IsAccessTokenRevoked(ctx context.Context,tokenId string) bool
}

// Auth code storage interface.
type AuthCodeRepositoryInterface interface {
	// Creates a new AuthCode
	GetNewAuthCode(ctx context.Context) AuthCodeEntityInterface
	// Persists a new auth code to permanent storage.
	PersistNewAuthCode(ctx context.Context,authCodeEntity AuthCodeEntityInterface) bool
	// Revoke an auth code.
	RevokeAuthCode(ctx context.Context,code string)
	// Check if the auth code has been revoked.
	IsAuthCodeRevoked(ctx context.Context,code string) bool
}

// Client storage interface.
type ClientRepositoryInterface interface {
	// Get a client.
	GetClientEntity(ctx context.Context,clientIdentifier string, grantType GrantType, clientSecret string, mustValidateSecret bool) ClientEntityInterface
}

// Refresh token interface
type RefreshTokenRepositoryInterface interface {
	// Creates a new refresh token
	GetNewRefreshToken(ctx context.Context) RefreshTokenEntityInterface
	// Create a new refresh token_name.
	PersistNewRefreshToken(ctx context.Context,refreshTokenEntity RefreshTokenEntityInterface) bool
	// Revoke the refresh token.
	RevokeRefreshToken(ctx context.Context,tokenId string)
	// Check if the refresh token has been revoked.
	IsRefreshTokenRevoked(ctx context.Context,tokenId string) bool
}

// Scope interface
type ScopeRepositoryInterface interface {
	// Return information about a scope.
	GetScopeEntityByIdentifier(ctx context.Context,identifier string) ScopeEntityInterface
	// Given a client, grant type and optional user identifier validate the set of scopes requested
	//   are valid and optionally append additional scopes or remove requested scopes.
	FinalizeScopes(ctx context.Context,scopes []ScopeEntityInterface, grantType GrantType, clientEntity ClientEntityInterface) []ScopeEntityInterface
}

type UserRepositoryInterface interface {
	// Get a user entity.
	GetUserEntityByUserCredentials(ctx context.Context,username string, password string, grantType string, clientEntity ClientEntityInterface) UserEntityInterface
}
