package oauth2

type ClientEntity struct {
	Entity
	Name           string
	RedirectUri    []string
	UserIdentifier string
}

func (a *ClientEntity) GetName() string {
	return a.Name
}

func (a *ClientEntity) GetRedirectUri() []string {
	return a.RedirectUri
}

func (a *ClientEntity) GetUserIdentifier() string {
	return a.UserIdentifier
}
