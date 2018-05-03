package oauth2

type AuthCodeEntity struct {
	Entity
	TokenEntity
	redirectUri string
}

func (a *AuthCodeEntity) GetRedirectUri() string  {
	return a.redirectUri
}

func (a *AuthCodeEntity) SetRedirectUri (uri string)  {
	a.redirectUri = uri
}