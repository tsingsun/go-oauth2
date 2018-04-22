package oauth2

type ClientEntity struct {
	Name string
	RedirectUri string
}

func (a *ClientEntity) GetName() string  {
	return a.Name
}


func (a *ClientEntity) GetRedirectUri() string  {
	return a.RedirectUri
}
