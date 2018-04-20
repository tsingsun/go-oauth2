package oauth2

import (
	"net/http"
)

type ResponseType struct {
	ResponseTypeInterface
	AccessToken  AccessTokenEntityInterface
	RefreshToken RefreshTokenEntityInterface
	PrivateKey   string
}

func (r ResponseType) SetAccessToken(accessToken AccessTokenEntityInterface) {
	r.AccessToken = accessToken
}
func (r ResponseType) SetRefreshToken(refreshToken RefreshTokenEntityInterface) {
	r.RefreshToken = refreshToken
}
func (r ResponseType) GenerateHttpResponse(response *http.Response) {

}
func (r ResponseType) SetEncryptionKey(key string) {
	r.PrivateKey = key
}
