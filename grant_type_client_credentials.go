package oauth2

import (
	"time"
	"github.com/tsingsun/go-oauth2/errors"
)

type ClientCredentialsGrant struct {
	Grant
	AccessTokenTTL time.Duration
}

func NewClientCredentialsGrant(options *Options) *ClientCredentialsGrant {
	grant := &ClientCredentialsGrant{}
	//child must explicit set grant type interface
	grant.Grant.GrantTypeInterface = grant
	grant.SetAccessTokenRepository(options.AccessTokenRepository)
	grant.SetClientRepository(options.ClientRepository)
	grant.SetScopeRepository(options.ScopeRepository)
	grant.AccessTokenTTL = 7200 * time.Second
	grant.SetEncryptionKey(options.EncryptionKey)
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

func (c *ClientCredentialsGrant) RespondToAccessTokenRequest(req *RequestWapper, res ResponseTypeInterface) (error) {
	client, err := c.validateClient(req)
	if err != nil {
		return err
	}
	scopes, _ := c.validateScopes(req.Scope)

	// Finalize the requested scopes
	finalizedScopes := c.scopeRepository.FinalizeScopes(scopes, c.GetIdentifier(), client, "");
	accessToken,err := c.issueAccessToken(c.AccessTokenTTL, client, "", finalizedScopes)
	if err !=nil{
		return err
	}
	res.SetAccessToken(accessToken)
	res.SetEncryptionKey(c.encryptionKey)
	return nil
}
