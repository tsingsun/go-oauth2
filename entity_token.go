package oauth2

import (
	"time"
)

type TokenEntity struct {
	scopes         map[string]ScopeEntityInterface
	expiryDataTime time.Time
	client         ClientEntityInterface
}

func (t *TokenEntity) AddScope(s ScopeEntityInterface) {
	if t.scopes == nil {
		t.scopes = make(map[string]ScopeEntityInterface)
	}
	t.scopes[s.GetIdentifier()] = s
}

func (t *TokenEntity) GetScopes() []ScopeEntityInterface {
	values := make([]ScopeEntityInterface, 0, len(t.scopes))
	for _, k := range t.scopes {
		values = append(values, k)
	}
	return values
}

func (t *TokenEntity) GetExpiryDateTime() time.Time {
	return t.expiryDataTime
}

func (t *TokenEntity) SetExpiryDateTime(time time.Time) {
	t.expiryDataTime = time
}

func (t *TokenEntity) GetClient() ClientEntityInterface {
	return t.client
}

func (t *TokenEntity) SetClient(e ClientEntityInterface) {
	t.client = e
}
