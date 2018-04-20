package oauth2

import (
	"github.com/dgrijalva/jwt-go"
)

type Crypt struct {
	EncryptionKey string
}

type OAuthClaims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Scopes    string `json:"scopes,omitempty"`
}

func EncryptJwt(claims OAuthClaims, publicKey string, privateKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims
	return token.SignedString([]byte(privateKey))
}

func DecryptJwt(tokenString string, publicKey string, privateKey string) (ret jwt.StandardClaims, err error) {
	var claims = jwt.StandardClaims{}
	token, e := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(privateKey), nil
	})
	if token.Valid {
		return
	}
	if e != nil {
		err = e
		return
	}
	ret = claims
	return
}

func (o OAuthClaims) Valid() error {
	return nil
}
