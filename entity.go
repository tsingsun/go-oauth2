package oauth2

type Entity struct {
	identifier string
}

func (a *Entity) getIdentifier() string  {
	return a.identifier
}


func (a *Entity) SetIdentifier(id string)  {
	a.identifier = id
}
