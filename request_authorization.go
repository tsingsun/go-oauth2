package oauth2

import "context"

// authorization request struct
type AuthorizationRequest struct {
	// The grant type identifier
	GrantType GrantType
	// The client identifier
	Client ClientEntityInterface
	// the User identifier
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
	// the request's context
	ctx context.Context
}

func (t AuthorizationRequest) SetContext(ctx context.Context)  {
	t.ctx = ctx
}
