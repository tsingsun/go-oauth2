package oauth2

import (
	"strings"
)

func ConvertScopes2String(scopes []ScopeEntityInterface) string {
	var vals []string
	for _, v := range scopes {
		vals = append(vals, v.GetIdentifier())
	}
	return strings.Join(vals, ",")
}
