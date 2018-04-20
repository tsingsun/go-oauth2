package oauth2

type TokenEntity struct {
	userIdentifier string
	client
}

func (a *Entity) getIdentifier() string  {
	return a.identifier
}


func (a *Entity) SetIdentifier(id string)  {
	a.identifier = id
}
