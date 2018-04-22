package oauth2_test

import (
	"github.com/tsingsun/go-oauth2"
	"testing"
)

var (
	defaultService *oauth2.Service
)

type Client struct {
	oauth2.Entity
	oauth2.ClientEntity
}

type ClientRepository struct {
	oauth2.ClientRepositoryInterface
	Db string
}

func (c *ClientRepository) GetClientEntity(clientIdentifier string, grantType oauth2.GrantType, clientSecret string, mustValidateSecret bool) oauth2.ClientEntityInterface {
	cl := &Client{
		Entity : oauth2.Entity{
			Identifier:"user01",
		},
		ClientEntity:oauth2.ClientEntity{
			Name:"name01",
			RedirectUri:"http://localhost",
		},
	}
	return cl
}

func TestNewService(t *testing.T) {
	var ce = &ClientRepository{}
	service := oauth2.NewService(oauth2.SetClientRepository(ce))
	if service.ClientRepository() != ce {
		t.Errorf("internal fail")
	}
}

func TestService_HandleAccessTokenRequest(t *testing.T) {
	tokenRequest := oauth2.TokenRequest{
		GrantType:oauth2.ClientCredentialGrantType,
		ClientId:"0001",
		ClientSecret:"abcdefasdf",
	}
	ret,err := defaultService.HandleAccessTokenRequest(tokenRequest)
	if err !=nil{
		t.Fatalf("get token error: %s",err)
	}
	if ret == nil {
		t.Fatal("get token error")
	}
}

func init() {

	defaultService = oauth2.NewService(
		oauth2.SetClientRepository(&ClientRepository{}),
		oauth2.SetGrantTypes(&oauth2.ClientCredentialsGrant{}),
	)
}