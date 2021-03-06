package oauth2_test

import (
	"context"
	"github.com/tsingsun/go-oauth2"
	"io/ioutil"
	"testing"
)

func TestNewService(t *testing.T) {
	var ce = &ClientRepository{}
	c,_ := ioutil.ReadFile(PRIVATE_KEY)
	service := oauth2.NewService(
		oauth2.WithClientRepository(ce),
		oauth2.WithPrivateKey(c),
	)
	if service.ClientRepository() != ce {
		t.Errorf("internal fail")
	}
}

func TestService_HandleAccessTokenRequest(t *testing.T) {
	tokenRequest := &oauth2.RequestWapper{
		GrantType:    oauth2.ClientCredentialGrantType,
		ClientId:     "0001",
		ClientSecret: "abcdefasdf",
		RedirectUri:  "http://localhost",
	}
	tokenRequest.SetContext(context.Background())
	ret, err := defaultService.HandleAccessTokenRequestInternal(tokenRequest)
	if err != nil {
		t.Fatalf("get token error: %s", err)
	}
	if ret == nil {
		t.Fatal("get token error")
	}
}
