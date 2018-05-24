package oauth2

type AuthorizationRequest struct {
	// The grant type identifier
	GrantType GrantType
	// The client identifier
	Client ClientEntityInterface
	//TODO
	User UserEntityInterface
	// An array of scope identifiers
	Scopes []ScopeEntityInterface
	// Has the user authorized the authorization request
	IsAuthorizationApproved bool
	// The redirect URI used in the request
	RedirectUri string
	// The state parameter on the authorization request
	State string
	// The code challenge (if provided)
	CodeChallenge string
	// The code challenge method (if provided)
	CodeChallengeMethod string
}
