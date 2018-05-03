package models

import "github.com/tsingsun/go-oauth2"

type User struct {
	oauth2.UserEntityInterface
	oauth2.UserRepositoryInterface
}

func (u *User) GetIdentifier() string {
	// must return web site current user
	return "0001"
}

func (u *User) GetUserEntityByUserCredentials(username string, password string, grantType string, clientEntity oauth2.ClientEntityInterface) oauth2.UserEntityInterface {
	return new(User)
}
