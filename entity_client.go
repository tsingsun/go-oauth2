package oauth2

type ClientEntity struct {
	name string
	redirectUri string
}

func (a *ClientEntity) GetName() string  {
	return a.name
}


func (a *ClientEntity) GetRedirectUri() string  {
	return a.redirectUri
}
