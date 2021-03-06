package oauth2

import (
	"context"
	"crypto/rsa"
	"errors"
	oauthError "github.com/tsingsun/go-oauth2/errors"
	"math/rand"
	"strings"
	"time"
)

type GrantType string

const (
	AuthCodeGrantType         GrantType = "authorization_code"
	ClientCredentialGrantType GrantType = "client_credentials"
	ImplicitGrantType         GrantType = "implicit"
	PasswordGrantType         GrantType = "password"
	RefreshTokenGrantType     GrantType = "refresh_token"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

type Grant struct {
	//GrantTypeInterface
	clientRepository      ClientRepositoryInterface
	scopeRepository       ScopeRepositoryInterface
	accessTokenRepository AccessTokenRepositoryInterface
	MaxGenerationAttempts int
	defaultScope          string
	Crypt
	privateKey *rsa.PrivateKey
}

// Validate Client Request
func (g *Grant) validateClient(rw *RequestWapper) (ClientEntityInterface, error) {
	grantType := rw.GrantType
	client := g.clientRepository.GetClientEntity(rw.ctx, rw.ClientId, grantType, rw.ClientSecret, true)

	if client == nil {
		return nil, oauthError.ErrInvalidClient
	}
	if err := g.validateRedirectUri(rw.RedirectUri, client); err != nil {
		return nil, err
	}
	return client, nil
}

func (g *Grant) validateRedirectUri(requestUri string, client ClientEntityInterface) error {
	if requestUri != "" {
		isInArray := false
		for _, v := range client.GetRedirectUri() {
			if v == requestUri {
				isInArray = true
				break
			}
		}
		if !isInArray {
			return oauthError.ErrInvalidRedirectUri
		}
	}
	return nil
}

func (g *Grant) validateScopes(ctx context.Context,scopeString string) (ret []ScopeEntityInterface, err error) {
	scopes := strings.SplitN(scopeString, ",", 0)
	for _, v := range scopes {
		scope := g.scopeRepository.GetScopeEntityByIdentifier(ctx,v)
		if scope == nil {
			err = oauthError.ErrInvalidScope
		}
		ret = append(ret, scope)
	}
	return ret, nil
}

func (g *Grant) issueAccessToken(ctx context.Context,ttl time.Duration, client ClientEntityInterface, scopes []ScopeEntityInterface) (AccessTokenEntityInterface, error) {
	accessToken := g.accessTokenRepository.GetNewToken(ctx,client, scopes, client.GetUserIdentifier())
	accessToken.SetClient(client)
	accessToken.SetExpiryDateTime(time.Now().Add(ttl))
	for _, v := range scopes {
		accessToken.AddScope(v)
	}
	maxGenerationAttempts := g.getMaxGenerationAttempts()
	for ; maxGenerationAttempts > 0; maxGenerationAttempts-- {
		accessToken.SetIdentifier(g.GenerateUniqueIdentifier(40))
		if g.accessTokenRepository.PersistNewAccessToken(ctx,accessToken) {
			return accessToken, nil
		}
	}
	return nil, errors.New("persist new access token error")
}

func (g *Grant) getMaxGenerationAttempts() int {
	if g.MaxGenerationAttempts == 0 {
		return 3
	}
	return g.MaxGenerationAttempts
}

func (g *Grant) GenerateUniqueIdentifier(n int) string {
	src := rand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func (g *Grant) SetAccessTokenRepository(accessTokenRepository AccessTokenRepositoryInterface) {
	g.accessTokenRepository = accessTokenRepository
}

func (g *Grant) SetClientRepository(clientRepository ClientRepositoryInterface) {
	g.clientRepository = clientRepository
}

func (g *Grant) SetScopeRepository(scopeRepository ScopeRepositoryInterface) {
	g.scopeRepository = scopeRepository
}

func (g *Grant) SetEncryptionKey(key []byte) {
	g.Crypt.SetEncryptionKey(key)
}

func (g *Grant) GetEncryptionKey() []byte {
	return g.encryptionKey
}

func (g *Grant) SetPrivateKey(key *rsa.PrivateKey) {
	g.privateKey = key
}

func (g *Grant) GetPrivateKey() *rsa.PrivateKey {
	return g.privateKey
}

func (g *Grant) SetDefaultScope(scope string) {
	g.defaultScope = scope
}
