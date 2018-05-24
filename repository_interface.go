package oauth2

// Access token interface.
type AccessTokenRepositoryInterface interface {
	// Create a new access token
	GetNewToken(ce ClientEntityInterface, scopes []ScopeEntityInterface, userIdentifier string) AccessTokenEntityInterface
	// Persists a new access token to permanent storage.
	PersistNewAccessToken(accessTokenEntity AccessTokenEntityInterface) bool
	// Revoke an access token.
	RevokeAccessToken(tokenId string)
	// Check if the access token has been revoked.
	IsAccessTokenRevoked(tokenId string) bool
}

// Auth code storage interface.
type AuthCodeRepositoryInterface interface {
	// Creates a new AuthCode
	GetNewAuthCode() AuthCodeEntityInterface
	// Persists a new auth code to permanent storage.
	PersistNewAuthCode(authCodeEntity AuthCodeEntityInterface) bool
	// Revoke an auth code.
	RevokeAuthCode(code string)
	// Check if the auth code has been revoked.
	IsAuthCodeRevoked(code string) bool
}

// Client storage interface.
type ClientRepositoryInterface interface {
	// Get a client.
	GetClientEntity(clientIdentifier string, grantType GrantType, clientSecret string, mustValidateSecret bool) ClientEntityInterface
}

// Refresh token interface
type RefreshTokenRepositoryInterface interface {
	// Creates a new refresh token
	GetNewRefreshToken() RefreshTokenEntityInterface
	// Create a new refresh token_name.
	PersistNewRefreshToken(refreshTokenEntity RefreshTokenEntityInterface) bool
	// Revoke the refresh token.
	RevokeRefreshToken(tokenId string)
	// Check if the refresh token has been revoked.
	IsRefreshTokenRevoked(tokenId string) bool
}

// Scope interface
type ScopeRepositoryInterface interface {
	// Return information about a scope.
	GetScopeEntityByIdentifier(identifier string) ScopeEntityInterface
	// Given a client, grant type and optional user identifier validate the set of scopes requested
	//   are valid and optionally append additional scopes or remove requested scopes.
	FinalizeScopes(scopes []ScopeEntityInterface, grantType GrantType, clientEntity ClientEntityInterface) []ScopeEntityInterface
}

type UserRepositoryInterface interface {
	// Get a user entity.
	GetUserEntityByUserCredentials(username string, password string, grantType string, clientEntity ClientEntityInterface) UserEntityInterface
}
