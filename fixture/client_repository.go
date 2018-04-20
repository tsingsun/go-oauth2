package main

import "github.com/tsingsun/go-oauth2"

type ClientRepository struct {
	Db string
}

func (c *ClientRepository) GetClientEntity(clientIdentifier string, grantType string, clientSecret string, mustValidateSecret bool) oauth2.ClientEntityInterface {
	return &ClientEntity{}
}
