package oauth2

type AuthCodeEntity struct {
	redirectUri string
}

func (a *AuthCodeEntity) GetRedirectUri() string  {
	return a.redirectUri
}

func (a *AuthCodeEntity) SetRedirectUri (uri string)  {
	a.redirectUri = uri
}