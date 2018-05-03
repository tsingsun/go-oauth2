package oauth2

import (
	"net/http"
	"time"
)

type BearerTokenResponse struct {
	ResponseTypeInterface
	AccessToken  AccessTokenEntityInterface
	RefreshToken RefreshTokenEntityInterface
	EncryptionKey   []byte
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
	r.EncryptionKey = key
}

func (r *BearerTokenResponse) GenerateResponse() *AccessTokenResponse {
	atoken := r.AccessToken.ConvertToJWT(r.EncryptionKey)
	ttl := (int)(r.AccessToken.GetExpiryDateTime().Sub(time.Now()).Seconds())
	ret := &AccessTokenResponse{
		AccessToken: atoken,
		ExpiresIn:   ttl,
		TokenType:   "bearer",
	}
	if r.RefreshToken != nil {
		ret.RefreshToken = r.RefreshToken.GetAccessToken().ConvertToJWT(r.EncryptionKey)
	}
	return ret
}