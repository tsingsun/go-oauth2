package oauth2

import (
	"net/http"
)

type ResponseTypeInterface interface {
	SetAccessToken(accessToken AccessTokenEntityInterface)
	SetRefreshToken(refreshToken RefreshTokenEntityInterface)
	GenerateHttpResponse(response *http.Response)
	SetEncryptionKey(key string)
}
