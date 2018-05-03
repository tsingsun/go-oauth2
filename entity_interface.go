package oauth2

import "time"

type TokenInterface interface {
	// Get the token's identifier.
	GetIdentifier() string
	// Set the token's identifier.
	SetIdentifier(identifier string)
	// Get the token's expiry date time.
	GetExpiryDateTime() time.Time
	// Set the date time when the token expires.
	SetExpiryDateTime(dateTime time.Time)
	// Set the identifier of the user associated with the token.
	SetUserIdentifier(identifier string)
	// Get the token user's identifier.
	GetUserIdentifier() string
	// Get the client that the token was issued to.
	GetClient() ClientEntityInterface
	// Set the client that the token was issued to.
	SetClient(client ClientEntityInterface)
	// Associate a scope with the token.
	AddScope(scope ScopeEntityInterface)
	// Return an array of scopes associated with the token.
	GetScopes() []ScopeEntityInterface
}

// TODO waiting
type AccessTokenEntityInterface interface {
	TokenInterface
	// Generate a JWT from the access token
	ConvertToJWT(signKey []byte) string
}

type AuthCodeEntityInterface interface {
	TokenInterface
	GetRedirectUri() string
	SetRedirectUri(uri string)
}

type ClientEntityInterface interface {
	// Get the client's identifier.
	GetIdentifier() string
	// Get the client's name.
	GetName() string
	// Returns the registered redirect URI (as a string).
	GetRedirectUri() []string
}

type RefreshTokenEntityInterface interface {
	// Get the token's identifier.
	GetIdentifier() string
	// Set the token's identifier.
	SetIdentifier(identifier string)
	// Get the token's expiry date time.
	GetExpiryDateTime() time.Time
	// Set the date time when the token expires.
	SetExpiryDateTime(time time.Time)
	// Set the access token that the refresh token was associated with.
	SetAccessToken(accessToken AccessTokenEntityInterface)
	// Get the access token that the refresh token was originally associated with.
	GetAccessToken() AccessTokenEntityInterface
}

type ScopeEntityInterface interface {
	// Get the scope's identifier.
	getIdentifier() string
}

type UserEntityInterface interface {
	// Get the user's identifier.
	GetIdentifier() string
}
