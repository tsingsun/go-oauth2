package oauth2

import (
	"net/http"
)

// Grant type interface.
type GrantTypeInterface interface {
	// Set refresh token TTL.
	SetRefreshTokenTTL(duration int)
	// Return the grant identifier that can be used in matching up requests.
	GetIdentifier() GrantType
	// TODO Respond to an incoming request.
	RespondToAccessTokenRequest(TokenRequest, ResponseTypeInterface) error
	/**
	 * TODO AuthorizationRequest
	 * If the grant can respond to an authorization request this method should be called to validate the parameters of
	 * the request.
	 *
	 * If the validation is successful an AuthorizationRequest object will be returned. This object can be safely
	 * serialized in a user's session, and can be used during user authentication and authorization.
	 */
	ValidateAuthorizationRequest(r *http.Request) *http.Request
	/**
	* Once a user has authenticated and authorized the client the grant can complete the authorization request.
	* The AuthorizationRequest object's $userId property must be set to the authenticated user and the
	* $authorizationApproved property must reflect their desire to authorize or deny the client.
	*
	 */
	CompleteAuthorizationRequest(r *http.Request)
	CanRespondToAccessTokenRequest(r *http.Request) bool
	// Set the client repository.
	SetClientRepository(clientRepository ClientRepositoryInterface)
	// Set the access token repository.
	SetAccessTokenRepository(accessTokenRepository AccessTokenRepositoryInterface)
	// Set the scope repository.
	SetScopeRepository(scopeRepository ScopeRepositoryInterface)
	// Set the path to the private key
	SetPrivateKey(privateKey string)
	// Set the encryption key
	SetEncryptionKey(key string)
}
