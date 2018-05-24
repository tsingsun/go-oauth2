package models

import "github.com/tsingsun/go-oauth2"

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
		Entity: oauth2.Entity{
			Identifier: "client01",
		},
		ClientEntity: oauth2.ClientEntity{
			Name:           "name01",
			RedirectUri:    []string{"http://localhost"},
			UserIdentifier: "user01",
		},
	}
	return cl
}
