package oauth2

type Entity struct {
	Identifier string
}

func (a *Entity) GetIdentifier() string  {
	return a.Identifier
}


func (a *Entity) SetIdentifier(id string)  {
	a.Identifier = id
}
