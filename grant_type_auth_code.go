package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	oauthErrors "github.com/tsingsun/go-oauth2/errors"
	"regexp"
	"time"
)

type AuthCodeGrant struct {
	Grant
	AuthCodeRepository       AuthCodeRepositoryInterface
	RefreshTokenRepository   RefreshTokenRepositoryInterface
	AuthCodeTTL              time.Duration
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	enabledCodeExchangeProof bool
}

type AuthCodePayload struct {
	UserID              string    `json:"user_id,omitempty"`
	ClientId            string    `json:"client_id,omitempty"`
	AuthCodeId          string    `json:"auth_code_id,omitempty"`
	ExpiresTime         time.Time `json:"expires_time"`
	Scopes              string    `json:"scopes,omitempty"`
	RedirectUri         string    `json:"redirect_uri,omitempty"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
}

var (
	SupportCodeChanllengeMethod = [2]string{"plain", "S256"}
)

func NewAuthCodeGrant(options *Options) *AuthCodeGrant {
	grant := &AuthCodeGrant{
		AuthCodeTTL:              10 * time.Minute, //default
		AccessTokenTTL:           1 * time.Hour,
		RefreshTokenTTL:          24 * time.Hour,
		AuthCodeRepository:       options.AuthCodeRepository,
		RefreshTokenRepository:   options.RefreshTokenRepository,
		enabledCodeExchangeProof: false,
	}
	grant.SetEncryptionKey(options.EncryptionKey)
	grant.SetClientRepository(options.ClientRepository)
	grant.SetScopeRepository(options.ScopeRepository)
	grant.SetAccessTokenRepository(options.AccessTokenRepository)
	return grant
}

func (g *AuthCodeGrant) EnableCodeExchangeProof() {
	g.enabledCodeExchangeProof = true
}

func (g *AuthCodeGrant) GetIdentifier() GrantType {
	return AuthCodeGrantType
}

func (g *AuthCodeGrant) SetAuthCodeTTL(duration time.Duration) {
	g.AuthCodeTTL = duration
}

func (g *AuthCodeGrant) SetAccessTokenTTL(duration time.Duration) {
	g.AccessTokenTTL = duration
}

func (g *AuthCodeGrant) SetRefreshTokenTTL(duration time.Duration) {
	g.RefreshTokenTTL = duration
}

func (g *AuthCodeGrant) CanRespondToAccessTokenRequest(request *RequestWapper) error {
	if request.GrantType != g.GetIdentifier() {
		return oauthErrors.ErrInvalidGrant
	}
	if request.ClientId == "" {
		return oauthErrors.ErrInvalidRequest
	}
	if request.ClientSecret == "" {
		return oauthErrors.ErrInvalidRequest
	}
	return nil
}

func (g *AuthCodeGrant) CanRespondToAuthorizationRequest(rw *RequestWapper) error {
	if rw.ResponseType != "code" {
		return oauthErrors.ErrInvalidGrant
	}
	if rw.ClientId == "" {
		return oauthErrors.ErrInvalidRequest
	}
	return nil
}

func (g *AuthCodeGrant) RespondToAccessTokenRequest(rw *RequestWapper, res ResponseTypeInterface) error {
	client, err := g.validateClient(rw)
	if err != nil {
		return err
	}
	plData, err := g.Decrypt(rw.Code)
	if err != nil {
		return oauthErrors.ErrInvalidRequest
	}
	payload := &AuthCodePayload{}
	if err := json.Unmarshal(plData, payload); err != nil {
		return oauthErrors.ErrInvalidRequest
	}

	if time.Now().After(payload.ExpiresTime) {
		// Authorization code has expired
		return oauthErrors.ErrInvalidAuthCode
	}

	if g.AuthCodeRepository.IsAuthCodeRevoked(payload.AuthCodeId) {
		//Authorization code has revoked
		return oauthErrors.ErrInvalidAuthCode
	}

	if payload.ClientId != client.GetIdentifier() {
		// Authorization code was not issued to this client
		return oauthErrors.ErrInvalidAuthCode
	}

	if rw.RedirectUri == "" && payload.RedirectUri != "" {
		return oauthErrors.ErrInvalidRedirectUri
	}

	if rw.RedirectUri != payload.RedirectUri {
		return oauthErrors.ErrInvalidRedirectUri

	}

	scopes, err := g.validateScopes(payload.Scopes)
	if err != nil {
		return err
	}

	scopes = g.scopeRepository.FinalizeScopes(scopes, g.GetIdentifier(), client)

	if g.enabledCodeExchangeProof {
		if rw.CodeVerifier == "" {
			// code_verifier
			return oauthErrors.ErrInvalidRequest
		}
		switch payload.CodeChallengeMethod {
		case "plain":
			if rw.CodeVerifier != payload.CodeChallenge {
				// Failed to verify `code_verifier`.
				return oauthErrors.ErrInvalidCodeVerifier
			}
		case "S256":
			h := sha256.New()
			h.Write([]byte(rw.CodeVerifier))
			if payload.CodeChallenge != base64.URLEncoding.EncodeToString(h.Sum(nil)) {
				return oauthErrors.ErrInvalidCodeVerifier
			}
		default:
			// Unsupported code challenge method
			return oauthErrors.ErrInvalidRequest
		}
	}
	accessToken, err := g.issueAccessToken(g.AccessTokenTTL, client, scopes)
	refreshToken, err := g.issueRefreshToken(accessToken)
	if err != nil {
		return err
	}
	res.SetEncryptionKey(g.encryptionKey)
	res.SetAccessToken(accessToken)
	res.SetRefreshToken(refreshToken)
	g.AuthCodeRepository.RevokeAuthCode(payload.AuthCodeId)
	return nil
}

func (g *AuthCodeGrant) ValidateAuthorizationRequest(rw *RequestWapper) (*AuthorizationRequest, error) {
	client := g.clientRepository.GetClientEntity(rw.ClientId, g.GetIdentifier(), "", false)
	if client == nil {
		return nil, oauthErrors.ErrInvalidClient
	}

	var rUri string = rw.RedirectUri
	if rw.RedirectUri != "" {
		if err := g.validateRedirectUri(rw.RedirectUri, client); err != nil {
			return nil, err
		}
	} else if len(client.GetRedirectUri()) != 1 {
		return nil, oauthErrors.ErrInvalidClient
	} else {
		rUri = client.GetRedirectUri()[0]
	}

	scopes, err := g.validateScopes(rw.Scope)
	if err != nil {
		return nil, err
	}

	ar := new(AuthorizationRequest)
	ar.GrantType = g.GetIdentifier()
	ar.Client = client
	ar.RedirectUri = rUri
	ar.State = rw.State
	ar.Scopes = scopes

	if g.enabledCodeExchangeProof {
		if rw.CodeChallenge == "" {
			err = oauthErrors.ErrInvalidRequest
			return nil, err
		}
		if ok, _ := regexp.MatchString("^[A-Za-z0-9-._~]{43,128}$", rw.CodeChallenge); !ok {
			err = oauthErrors.ErrInvalidCodeChallenge
			return nil, err
		}
		if rw.CodeChallengeMethod != SupportCodeChanllengeMethod[0] && rw.CodeChallengeMethod != SupportCodeChanllengeMethod[1] {
			err = oauthErrors.ErrInvalidCodeChallengeMethod
			return nil, err
		}
		ar.CodeChallenge = rw.CodeChallenge
		ar.CodeChallengeMethod = rw.CodeChallengeMethod
	}

	return ar, nil
}

func (g *AuthCodeGrant) CompleteAuthorizationRequest(ar *AuthorizationRequest) (*RedirectTypeResponse, error) {
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
		authCode, err := g.issueAuthCode(g.AuthCodeTTL, ar.Client, ar.RedirectUri, ar.Scopes)
		if err != nil {
			return nil, err
		}

		payload := AuthCodePayload{
			ClientId:            authCode.GetClient().GetIdentifier(),
			RedirectUri:         authCode.GetRedirectUri(),
			AuthCodeId:          authCode.GetIdentifier(),
			Scopes:              ConvertScopes2String(authCode.GetScopes()),
			UserID:              authCode.GetClient().GetUserIdentifier(),
			ExpiresTime:         time.Now().Add(g.AuthCodeTTL),
			CodeChallenge:       ar.CodeChallenge,
			CodeChallengeMethod: ar.CodeChallengeMethod,
		}
		bData, _ := json.Marshal(payload)
		code, err := g.Encrypt(bData)
		if err != nil {
			return nil, err
		}
		params := map[string]string{
			"code":  code,
			"state": ar.State,
		}
		res := &RedirectTypeResponse{
			RedirectUri: MakeRedirectUri(finalRedirectUri, params, "#"),
		}
		return res, nil
	}
	return nil, oauthErrors.ErrAccessDenied
}

func (g *AuthCodeGrant) issueAuthCode(ttl time.Duration, client ClientEntityInterface, redirectUri string, scopes []ScopeEntityInterface) (AuthCodeEntityInterface, error) {
	authCode := g.AuthCodeRepository.GetNewAuthCode()
	authCode.SetExpiryDateTime(time.Now().Add(ttl))
	authCode.SetClient(client)
	authCode.SetRedirectUri(redirectUri)
	for _, v := range scopes {
		authCode.AddScope(v)
	}
	for maxGenerationAttempts := g.getMaxGenerationAttempts(); maxGenerationAttempts > 0; maxGenerationAttempts-- {
		authCode.SetIdentifier(g.GenerateUniqueIdentifier(40))
		if g.AuthCodeRepository.PersistNewAuthCode(authCode) {
			return authCode, nil
		}
	}
	// persist new auth code error
	return nil, oauthErrors.ErrPersistNewError
}

func (g *AuthCodeGrant) issueRefreshToken(accessToken AccessTokenEntityInterface) (RefreshTokenEntityInterface, error) {
	refreshToken := g.RefreshTokenRepository.GetNewRefreshToken()
	refreshToken.SetExpiryDateTime(time.Now().Add(g.RefreshTokenTTL))
	refreshToken.SetAccessToken(accessToken)
	for maxGenerationAttempts := g.getMaxGenerationAttempts(); maxGenerationAttempts > 0; maxGenerationAttempts-- {
		refreshToken.SetIdentifier(g.GenerateUniqueIdentifier(40))
		if g.RefreshTokenRepository.PersistNewRefreshToken(refreshToken) {
			return refreshToken, nil
		}
	}
	return nil, errors.New("persist refresh token error")
}
