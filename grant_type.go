package oauth2

import (
	"errors"
	oerror "github.com/tsingsun/go-oauth2/errors"
	"strings"
	"time"
	"math/rand"
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
	GrantTypeInterface
	clientRepository      ClientRepositoryInterface
	scopeRepository       ScopeRepositoryInterface
	accessTokenRepository AccessTokenRepositoryInterface
	maxGenerationAttempts int
}

// Validate Client Request
func (g *Grant) validateClient(request TokenRequest) (ClientEntityInterface, error) {
	if e := request.Validate(); e != nil {
		return nil, e
	}

	if request.ClientId == "" && request.Username != "" {
		request.ClientId = request.Username
	}

	if request.ClientSecret != "" && request.Password != "" {
		request.ClientSecret = request.Password
	}

	if request.ClientId == "" {
		return nil, errors.New("invalid request,miss client_id")
	}

	client := g.clientRepository.GetClientEntity(request.ClientId, g.GetIdentifier(), request.ClientSecret, true)

	if client == nil {
		return nil, oerror.NewInvalidClient()
	}

	if request.RedirectUri != client.GetRedirectUri() {
		return nil, errors.New("invalid request,incoret redirect uri")
	}
	return client, nil
}

func (g *Grant) validateScopes(scopeString string, redirectUri string) (ret []ScopeEntityInterface, err error) {
	scopes := strings.SplitN(scopeString, ",", 0)
	for _, v := range scopes {
		scope := g.scopeRepository.GetScopeEntityByIdentifier(v)
		ret = append(ret, scope)
	}
	return ret, nil
}

func (g *Grant) issueAccessToken(ttl int64, client ClientEntityInterface, userIdentifier string, scopes []ScopeEntityInterface) AccessTokenEntityInterface {
	accessToken := g.accessTokenRepository.GetNewToken(client, scopes, userIdentifier)
	accessToken.SetClient(client)
	accessToken.SetUserIdentifier(userIdentifier)
	accessToken.SetExpiryDateTime(time.Now().Add(time.Duration(ttl) * time.Second))
	for _, v := range scopes {
		accessToken.AddScope(v)
	}
	for ; g.maxGenerationAttempts > 0; g.maxGenerationAttempts-- {
		accessToken.SetIdentifier(g.GenerateUniqueIdentifier(40))
		if g.accessTokenRepository.PersistNewAccessToken(accessToken) {
			return accessToken
		}
	}
	return nil
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
