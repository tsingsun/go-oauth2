package oauth2

import (
	"errors"
	oauthErrors "github.com/tsingsun/go-oauth2/errors"
	"strconv"
	"time"
)

type ImplicitGrant struct {
	Grant
	AccessTokenTTL time.Duration
}

func NewImplicitGrant(options *Options) *ImplicitGrant {
	grant := &ImplicitGrant{}
	//child must explicit set grant type interface
	grant.SetAccessTokenRepository(options.AccessTokenRepository)
	grant.SetClientRepository(options.ClientRepository)
	grant.SetScopeRepository(options.ScopeRepository)
	grant.AccessTokenTTL = 7200 * time.Second
	grant.SetEncryptionKey(options.EncryptionKey)
	grant.SetPrivateKey(options.PrivateKey)
	return grant
}

func (g *ImplicitGrant) SetAccessTokenTTL(duration time.Duration) {
	g.AccessTokenTTL = duration
}

func (g *ImplicitGrant) GetIdentifier() GrantType {
	return ImplicitGrantType
}

func SetRefreshTokenTTL(duration time.Duration) {
	panic("The Implicit Grant does not return refresh tokens")
}

func setRefreshTokenRepository(refreshTokenRepository RefreshTokenRepositoryInterface) {
	panic("The Implicit Grant does not return refresh tokens")
}

func (c *ImplicitGrant) CanRespondToAccessTokenRequest(request *RequestWapper) error {
	return oauthErrors.ErrInvalidGrant
}

func (c *ImplicitGrant) RespondToAccessTokenRequest(request *RequestWapper, responseType ResponseTypeInterface) error {
	return oauthErrors.ErrInvalidGrant
}

func (c *ImplicitGrant) CanRespondToAuthorizationRequest(request *RequestWapper) error {
	if request.ResponseType != "token" {
		return oauthErrors.ErrInvalidGrant
	}
	if request.ClientId == "" {
		return oauthErrors.ErrInvalidRequest
	}
	return nil
}

func (c *ImplicitGrant) ValidateAuthorizationRequest(rw *RequestWapper) (*AuthorizationRequest, error) {
	client := c.clientRepository.GetClientEntity(rw.ctx, rw.ClientId, c.GetIdentifier(), "", false)
	if client == nil {
		return nil, oauthErrors.ErrInvalidClient
	}
	var rUri string = rw.RedirectUri
	if rw.RedirectUri != "" {
		if err := c.validateRedirectUri(rw.RedirectUri, client); err != nil {
			return nil, err
		}
	} else if len(client.GetRedirectUri()) != 1 {
		return nil, oauthErrors.ErrInvalidClient
	} else {
		rUri = client.GetRedirectUri()[0]
	}

	scopes, err := c.validateScopes(rw.ctx,rw.Scope)
	if err != nil {
		return nil, err
	}
	scopes = c.scopeRepository.FinalizeScopes(rw.ctx, scopes, c.GetIdentifier(), client)
	authorizationRequest := &AuthorizationRequest{
		GrantType:   c.GetIdentifier(),
		Client:      client,
		RedirectUri: rUri,
		State:       rw.State,
		Scopes:      scopes,
		ctx:         rw.ctx,
	}
	return authorizationRequest, nil
}

func (c *ImplicitGrant) CompleteAuthorizationRequest(ar *AuthorizationRequest) (*RedirectTypeResponse, error) {
	if ar.User == nil {
		return nil, errors.New("An instance of UserEntityInterface should be set on the AuthorizationRequest")
	}
	var finalRedirectUri string
	if ar.RedirectUri == "" {
		if len(ar.Client.GetRedirectUri()) > 1 {
			finalRedirectUri = ar.Client.GetRedirectUri()[0]
		} else {
			finalRedirectUri = ""
		}
	} else {
		finalRedirectUri = ar.RedirectUri
	}

	if ar.IsAuthorizationApproved {
		accessToken, err := c.issueAccessToken(ar.ctx,c.AccessTokenTTL, ar.Client, ar.Scopes)
		if err != nil {
			return nil, err
		}
		var atStr string
		atStr, err = accessToken.ConvertToJWT(c.privateKey)
		if err != nil {
			return nil, err
		}
		ttl := (int)(accessToken.GetExpiryDateTime().Sub(time.Now()).Seconds())
		params := map[string]string{
			"access_token": atStr,
			"token_type":   "bearer",
			"expires_in":   strconv.Itoa(ttl),
			"state":        ar.State,
		}
		res := &RedirectTypeResponse{
			RedirectUri: MakeRedirectUri(finalRedirectUri, params, "#"),
		}
		return res, nil
	}
	return nil, oauthErrors.ErrAccessDenied
}
