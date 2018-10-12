package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	oauthErrors "github.com/tsingsun/go-oauth2/errors"
	"time"
)

type RefreshTokenGrant struct {
	Grant
	AccessTokenTTL         time.Duration
	RefreshTokenTTL        time.Duration
	RefreshTokenRepository RefreshTokenRepositoryInterface
}

type RefreshTokenPayload struct {
	UserID         string    `json:"user_id,omitempty"`
	ClientId       string    `json:"client_id,omitempty"`
	RefreshTokenId string    `json:"refresh_token_id,omitempty"`
	AccessTokenId  string    `json:"access_token_id,omitempty"`
	ExpiresTime    time.Time `json:"expires_time"`
	Scopes         string    `json:"scopes,omitempty"`
}

func NewRefreshTokenGrant(options *Options) *RefreshTokenGrant {
	grant := &RefreshTokenGrant{
		RefreshTokenTTL:        24 * time.Hour,
		RefreshTokenRepository: options.RefreshTokenRepository,
	}
	grant.SetEncryptionKey(options.EncryptionKey)
	grant.SetClientRepository(options.ClientRepository)
	grant.SetScopeRepository(options.ScopeRepository)
	grant.SetAccessTokenRepository(options.AccessTokenRepository)
	grant.SetPrivateKey(options.PrivateKey)
	return grant
}

func (t *RefreshTokenGrant) SetRefreshTokenTTL(duration time.Duration) {
	t.RefreshTokenTTL = duration
}

func (t *RefreshTokenGrant) SetAccessTokenTTL(duration time.Duration) {
	t.AccessTokenTTL = duration
}

func (t *RefreshTokenGrant) GetIdentifier() GrantType {
	return RefreshTokenGrantType
}

func (t *RefreshTokenGrant) CanRespondToAccessTokenRequest(request *RequestWapper) error {
	if request.GrantType != t.GetIdentifier() {
		return oauthErrors.ErrInvalidGrant
	}
	return nil
}

func (t *RefreshTokenGrant) RespondToAccessTokenRequest(rw *RequestWapper, res ResponseTypeInterface) error {
	client, err := t.validateClient(rw)
	if err != nil {
		return err
	}
	payload, err := t.validateOldRefreshToken(rw, client.GetIdentifier())
	if err != nil {
		return err
	}

	var reqScopes string
	if rw.Scope != "" {
		reqScopes = rw.Scope
	} else {
		reqScopes = payload.Scopes
	}

	scopes, err := t.validateScopes(rw.ctx,reqScopes)
	if err != nil {
		return err
	}

	t.accessTokenRepository.RevokeAccessToken(rw.ctx,payload.AccessTokenId)
	t.RefreshTokenRepository.RevokeRefreshToken(rw.ctx,payload.RefreshTokenId)

	accessToken, err := t.issueAccessToken(rw.ctx,t.AccessTokenTTL, client, scopes)
	refreshToken, err := t.issueRefreshToken(rw.ctx,accessToken)
	if err != nil {
		return err
	}
	res.SetEncryptionKey(t.encryptionKey)
	res.SetAccessToken(accessToken)
	res.SetRefreshToken(refreshToken)

	return nil
}

func (t *RefreshTokenGrant) validateOldRefreshToken(rw *RequestWapper, clientId string) (*RefreshTokenPayload, error) {
	plData, err := t.Decrypt(rw.RefreshToken)
	if err != nil {
		return nil, oauthErrors.ErrInvalidRequest
	}
	payload := &RefreshTokenPayload{}
	if err = json.Unmarshal(plData, payload); err != nil {
		return nil, oauthErrors.ErrInvalidRequest
	}

	if time.Now().After(payload.ExpiresTime) {
		// Authorization code has expired
		return nil, oauthErrors.ErrInvalidAuthCode
	}

	if payload.ClientId != clientId {
		// Authorization code was not issued to this client
		return nil, oauthErrors.ErrInvalidAuthCode
	}
	if t.RefreshTokenRepository.IsRefreshTokenRevoked(rw.ctx,payload.RefreshTokenId) {
		return nil, oauthErrors.ErrInvalidRefreshToken
	}
	return payload, nil
}

func (t *RefreshTokenGrant) issueRefreshToken(ctx context.Context,accessToken AccessTokenEntityInterface) (RefreshTokenEntityInterface, error) {
	refreshToken := t.RefreshTokenRepository.GetNewRefreshToken(ctx)
	refreshToken.SetExpiryDateTime(time.Now().Add(t.RefreshTokenTTL))
	refreshToken.SetAccessToken(accessToken)
	for maxGenerationAttempts := t.getMaxGenerationAttempts(); maxGenerationAttempts > 0; maxGenerationAttempts-- {
		refreshToken.SetIdentifier(t.GenerateUniqueIdentifier(40))
		if t.RefreshTokenRepository.PersistNewRefreshToken(ctx,refreshToken) {
			return refreshToken, nil
		}
	}
	return nil, errors.New("persist refresh token error")
}

func (t *RefreshTokenGrant) CanRespondToAuthorizationRequest(request *RequestWapper) error {
	return oauthErrors.ErrInvalidGrant
}

func (t *RefreshTokenGrant) CompleteAuthorizationRequest(ar *AuthorizationRequest) (*RedirectTypeResponse, error) {
	return nil, oauthErrors.ErrInvalidGrant
}

func (t *RefreshTokenGrant) ValidateAuthorizationRequest(request *RequestWapper) (*AuthorizationRequest, error) {
	return nil, oauthErrors.ErrInvalidGrant
}
