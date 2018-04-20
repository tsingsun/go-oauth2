package oauth2

type ClientCredentialsGrant struct {
	Grant
}

func NewClientCredentialsGrant(options *Options) *ClientCredentialsGrant {
	grant := &ClientCredentialsGrant{}

	grant.SetAccessTokenRepository(options.AccessTokenRepository)
	grant.SetClientRepository(options.ClientRepository)
	grant.SetScopeRepository(options.ScopeRepository)

	return grant
}

func (c *ClientCredentialsGrant) GetIdentifier() GrantType {
	return ClientCredentialGrantType
}

func (c *ClientCredentialsGrant) RespondToAccessTokenRequest(req TokenRequest, res ResponseTypeInterface) error {
	client, err := c.validateClient(req)
	if err != nil {
		return err
	}
	scopes, _ := c.validateScopes(req.Scope, req.RedirectUri)

	accessToken := c.issueAccessToken(3600, client, "", scopes)
	res.SetAccessToken(accessToken)
	return nil
}
