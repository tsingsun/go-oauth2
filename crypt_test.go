package oauth2_test

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/tsingsun/go-oauth2"
	"testing"
	"time"
)

var (
	SecretKey string = "abdcadfasdf"
)

func TestParseJwt(t *testing.T) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := jwt.StandardClaims{}
	claims.ExpiresAt = time.Now().Add(time.Hour * time.Duration(1)).Unix()
	claims.IssuedAt = time.Now().Unix()
	//claims.Scopes = "a"
	token.Claims = claims

	tokenString, _ := token.SignedString([]byte(SecretKey))
	val1, _ := oauth2.DecryptJwt(tokenString, "", SecretKey)
	if val1.ExpiresAt != claims.ExpiresAt {
		t.Error("value false")
	}
}
