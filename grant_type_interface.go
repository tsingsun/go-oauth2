package oauth2

import "crypto/rsa"

// Grant type interface.
type GrantTypeInterface interface {
	// Return the grant identifier that can be used in matching up requests.
	GetIdentifier() GrantType
	// TODO Respond to an incoming request.
	RespondToAccessTokenRequest(request *RequestWapper, responseType ResponseTypeInterface) error
	/**
	 * TODO AuthorizationRequest
	 * If the grant can respond to an authorization request this method should be called to validate the parameters of
	 * the request.
	 *
	 * If the validation is successful an AuthorizationRequest object will be returned. This object can be safely
	 * serialized in a user's session, and can be used during user authentication and authorization.
	 */
	ValidateAuthorizationRequest(request *RequestWapper) (*AuthorizationRequest, error)
	/**
	* Once a user has authenticated and authorized the client the grant can complete the authorization request.
	* The AuthorizationRequest object's $userId property must be set to the authenticated user and the
	* authorizationApproved property must reflect their desire to authorize or deny the client.
	*
	 */
	CompleteAuthorizationRequest(authorizationRequest *AuthorizationRequest) (*RedirectTypeResponse, error)
	// The grant type should return true if it is able to response to an token request
	CanRespondToAccessTokenRequest(request *RequestWapper) error
	// The grant type should return true if it is able to response to an authorization request
	CanRespondToAuthorizationRequest(request *RequestWapper) error
	// Set the client repository.
	SetClientRepository(clientRepository ClientRepositoryInterface)
	// Set the access token repository.
	SetAccessTokenRepository(accessTokenRepository AccessTokenRepositoryInterface)
	// Set the scope repository.
	SetScopeRepository(scopeRepository ScopeRepositoryInterface)
	// Set the path to the private key
	SetPrivateKey(privateKey *rsa.PrivateKey)
	// Set the encryption key
	SetEncryptionKey(key []byte)
	// Get the encryption key
	GetEncryptionKey() []byte
	// Get the path to the private key
	GetPrivateKey() *rsa.PrivateKey
}
