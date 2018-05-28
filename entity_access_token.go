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

// Structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
// See examples for how to use this with your own claim types
type JwtPayloadClaims struct {
	jwt.StandardClaims
	Scopes string `json:"scopes,omitempty"`
}

func (a *AccessTokenEntity) ConvertToJWT(signKey interface{}) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	claims := JwtPayloadClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  a.GetClient().GetIdentifier(),
			ExpiresAt: a.GetExpiryDateTime().Unix(),
			Id:        a.GetIdentifier(),
			IssuedAt:  time.Now().Unix(),
			Subject:   a.GetClient().GetUserIdentifier(),
		},
		Scopes: ConvertScopes2String(a.GetScopes()),
	}

	token.Claims = claims

	if tokenString, err := token.SignedString(signKey); err != nil {
		return "", err
	} else {
		return tokenString, nil
	}
}
