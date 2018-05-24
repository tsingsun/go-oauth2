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

func (a *AccessTokenEntity) ConvertToJWT(signKey []byte) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := jwt.StandardClaims{
		ExpiresAt: a.GetExpiryDateTime().Unix(),
		IssuedAt:  time.Now().Unix(),
		Audience:  a.GetClient().GetUserIdentifier(),
		Subject:   ConvertScopes2String(a.GetScopes()),
		Id:        a.GetIdentifier(),
	}

	token.Claims = claims

	if tokenString, err := token.SignedString(signKey); err != nil {
		return "", err
	} else {
		return tokenString, nil
	}
}
