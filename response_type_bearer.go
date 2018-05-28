package oauth2

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"time"
)

type BearerTokenResponse struct {
	AccessToken  AccessTokenEntityInterface
	RefreshToken RefreshTokenEntityInterface
	Crypt
	PrivateKey *rsa.PrivateKey
}

func (r *BearerTokenResponse) SetAccessToken(accessToken AccessTokenEntityInterface) {
	r.AccessToken = accessToken
}

func (r *BearerTokenResponse) SetRefreshToken(refreshToken RefreshTokenEntityInterface) {
	r.RefreshToken = refreshToken
}

func (r *BearerTokenResponse) GenerateHttpResponse(response *http.Response) {
	response.StatusCode = 200
}

func (r *BearerTokenResponse) SetEncryptionKey(key []byte) {
	r.Crypt.SetEncryptionKey(key)
}

func (r *BearerTokenResponse) SetPrivateKey(key *rsa.PrivateKey) {
	r.PrivateKey = key
}

func (r *BearerTokenResponse) GenerateResponse() *AccessTokenResponse {
	atoken, err := r.AccessToken.ConvertToJWT(r.PrivateKey)

	if err != nil {
		return &AccessTokenResponse{
			Error: err,
		}
	}
	ttl := int32(r.AccessToken.GetExpiryDateTime().Unix() - time.Now().Unix())
	ret := &AccessTokenResponse{
		AccessToken: atoken,
		ExpiresIn:   ttl,
		TokenType:   "bearer",
	}
	if r.RefreshToken != nil {
		payload := &RefreshTokenPayload{
			ClientId:       r.AccessToken.GetClient().GetIdentifier(),
			RefreshTokenId: r.RefreshToken.GetIdentifier(),
			AccessTokenId:  r.AccessToken.GetIdentifier(),
			Scopes:         ConvertScopes2String(r.AccessToken.GetScopes()),
			UserID:         r.AccessToken.GetClient().GetUserIdentifier(),
			ExpiresTime:    r.RefreshToken.GetExpiryDateTime(),
		}
		bData, _ := json.Marshal(payload)
		tData, err := r.Encrypt(bData)
		if err != nil {
			ret.Error = err
		}
		ret.RefreshToken = tData
	}
	return ret
}
