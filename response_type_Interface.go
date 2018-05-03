package oauth2

import "net/http"

type ResponseTypeInterface interface {
	// Set accessToken entity
	SetAccessToken(accessToken AccessTokenEntityInterface)
	SetRefreshToken(refreshToken RefreshTokenEntityInterface)
	//
	GenerateHttpResponse(response *http.Response)
	GenerateResponse() *AccessTokenResponse
	SetEncryptionKey(key []byte)
}
