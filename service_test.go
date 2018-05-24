package oauth2_test

import (
	"github.com/tsingsun/go-oauth2"
	"testing"
)

func TestNewService(t *testing.T) {
	var ce = &ClientRepository{}
	service := oauth2.NewService(oauth2.SetClientRepository(ce))
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
	ret, err := defaultService.HandleAccessTokenRequestInternal(tokenRequest)
	if err != nil {
		t.Fatalf("get token error: %s", err)
	}
	if ret == nil {
		t.Fatal("get token error")
	}
}
