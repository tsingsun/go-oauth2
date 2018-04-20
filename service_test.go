package oauth2_test

import (
	"github.com/tsingsun/go-oauth2"
	"testing"
)

var (
	defaultService *oauth2.Service
)

type ClientEntity struct {
	oauth2.ClientEntityInterface
	id   string
	name string
}

func (c *ClientEntity) GetIdentifier() string {
	return string("id001")
}

func (c *ClientEntity) GetName() string {
	return string(c.name)
}

func (c *ClientEntity) GetRedirectUri() string {
	return string("http://localhost")
}

type ClientRepository struct {
	oauth2.ClientRepositoryInterface
	Db string
}

func (c *ClientRepository) GetClientEntity(clientIdentifier string, grantType oauth2.GrantType, clientSecret string, mustValidateSecret bool) oauth2.ClientEntityInterface {
	return &ClientEntity{
		name: clientIdentifier,
	}
}

func TestNewService(t *testing.T) {
	var ce = &ClientRepository{}
	service := oauth2.NewService(oauth2.SetClientRepository(ce))
	if service.ClientRepository() != ce {
		t.Errorf("internal fail")
	}
}

func init() {

	defaultService = oauth2.NewService(
		oauth2.SetClientRepository(&ClientRepository{}),
	)
}