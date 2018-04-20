package main

type ClientEntity struct {
}

func (c *ClientEntity) GetIdentifier() (string, bool) {
	return "id001", false
}

func (c *ClientEntity) GetName() string {
	return "user001"
}

func (c *ClientEntity) GetRedirectUri() string {
	return "http://localhost"
}
