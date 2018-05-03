package oauth2

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

// implement AccessTokenEntityInterface
type AccessTokenEntity struct {
	TokenEntity
	Entity
}

func (a *AccessTokenEntity) ConvertToJWT(signKey []byte) string  {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := jwt.StandardClaims{}
	claims.ExpiresAt = a.GetExpiryDateTime().Unix()
	claims.IssuedAt = time.Now().Unix()
	claims.Subject = ConvertScopes2String(a.GetScopes())
	token.Claims = claims

	tokenString, _ := token.SignedString(signKey)
	//TODO error handle
	return tokenString
}