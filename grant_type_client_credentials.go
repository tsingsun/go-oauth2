package oauth2

import (
	"github.com/tsingsun/go-oauth2/errors"
	"time"
)

type ClientCredentialsGrant struct {
	Grant
	AccessTokenTTL time.Duration
}

func NewClientCredentialsGrant(options *Options) *ClientCredentialsGrant {
	grant := &ClientCredentialsGrant{}
	//child must explicit set grant type interface
	grant.SetAccessTokenRepository(options.AccessTokenRepository)
	grant.SetClientRepository(options.ClientRepository)
	grant.SetScopeRepository(options.ScopeRepository)
	grant.AccessTokenTTL = 2 * time.Hour
	grant.SetEncryptionKey(options.EncryptionKey)
	grant.SetPrivateKey(options.PrivateKey)
	return grant
}

func (c *ClientCredentialsGrant) SetAccessTokenTTL(duration time.Duration) {
	c.AccessTokenTTL = duration
}

func (c *ClientCredentialsGrant) GetIdentifier() GrantType {
	return ClientCredentialGrantType
}

// Validate simply  the request
func (c *ClientCredentialsGrant) CanRespondToAccessTokenRequest(request *RequestWapper) error {
	if request.GrantType != c.GetIdentifier() {
		return errors.ErrInvalidGrant
	}
	if request.ClientId == "" {
		return errors.ErrInvalidRequest
	}
	if request.ClientSecret == "" {
		return errors.ErrInvalidRequest
	}
	return nil
}

func (c *ClientCredentialsGrant) RespondToAccessTokenRequest(rw *RequestWapper, res ResponseTypeInterface) error {
	client, err := c.validateClient(rw)
	if err != nil {
		return err
	}
	scopes, _ := c.validateScopes(rw.ctx,rw.Scope)

	// Finalize the requested scopes
	finalizedScopes := c.scopeRepository.FinalizeScopes(rw.ctx,scopes, c.GetIdentifier(), client)
	accessToken, err := c.issueAccessToken(rw.ctx,c.AccessTokenTTL, client, finalizedScopes)
	if err != nil {
		return err
	}
	res.SetAccessToken(accessToken)
	res.SetEncryptionKey(c.encryptionKey)
	return nil
}

func (c *ClientCredentialsGrant) CanRespondToAuthorizationRequest(request *RequestWapper) error {
	return errors.ErrInvalidGrant
}

func (c *ClientCredentialsGrant) CompleteAuthorizationRequest(authorizationRequest *AuthorizationRequest) (*RedirectTypeResponse, error) {
	return nil, errors.ErrInvalidGrant
}

func (c *ClientCredentialsGrant) ValidateAuthorizationRequest(request *RequestWapper) (*AuthorizationRequest, error) {
	return nil, errors.ErrInvalidGrant
}
