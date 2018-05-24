package models

import "github.com/tsingsun/go-oauth2"

type Scope struct {
	Id   string
	Name string
	oauth2.Entity
	oauth2.ScopeEntityInterface
	oauth2.ScopeRepositoryInterface
}

func (s *Scope) getIdentifier() string {
	return s.Id
}

func (s *Scope) GetScopeEntityByIdentifier(identifier string) oauth2.ScopeEntityInterface {
	sps := make(map[string]string)
	sps["basic"] = "basic info"
	sps["social"] = "get info"

	return &Scope{Id: "basic", Name: "basic info"}
}

func (s *Scope) FinalizeScopes(scopes []oauth2.ScopeEntityInterface, grantType oauth2.GrantType, clientEntity oauth2.ClientEntityInterface, userIdentifier string) []oauth2.ScopeEntityInterface {
	return []oauth2.ScopeEntityInterface{&Scope{Id: "basic", Name: "basic info"}}
}
