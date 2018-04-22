package oauth2

import (
	"time"
)

type TokenEntity struct {
	scopes map[string]ScopeEntityInterface
	expiryDataTime time.Time
	userIdentifier string
	client ClientEntityInterface
}

func (t *TokenEntity) AddScope(s ScopeEntityInterface)  {
	t.scopes[s.getIdentifier()] = s
}


func (t *TokenEntity) GetScopes() []ScopeEntityInterface  {
	values := make([]ScopeEntityInterface,0,len(t.scopes))
	for _,k:=range t.scopes {
		values = append(values,k)
	}
	return values
}

func (t *TokenEntity)GetExpiryDateTime() time.Time  {
	return t.expiryDataTime
}

func (t *TokenEntity)SetExpiryDateTime(time time.Time)   {
	t.expiryDataTime = time
}

func (t *TokenEntity)SetUserIdentity(identity string)  {
	t.userIdentifier = identity
}
func (t *TokenEntity)GetUserIdentity() string  {
	return t.userIdentifier
}

func (t *TokenEntity) GetClient() ClientEntityInterface {
	return t.client
}

func (t *TokenEntity)SetClient(e ClientEntityInterface)  {
	t.client = e
}

