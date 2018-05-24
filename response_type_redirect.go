package oauth2

import (
	"net/http"
	"net/url"
	"strings"
)

type RedirectTypeResponse struct {
	AccessToken AccessTokenEntityInterface
	RedirectUri string
	PrivateKey  string
}

func (r *RedirectTypeResponse) SetAccessToken(accessToken AccessTokenEntityInterface) {
	r.AccessToken = accessToken
}

func (r *RedirectTypeResponse) SetEncryptionKey(key string) {
	r.PrivateKey = key
}

func (r *RedirectTypeResponse) GenerateHttpResponse(w http.ResponseWriter) {
	w.Header().Set("Location", r.RedirectUri)
	w.WriteHeader(302)
}

func MakeRedirectUri(uri string, params map[string]string, queryDelimiter string) string {
	if strings.Index(uri, "?") != -1 {
		queryDelimiter = "&"
	}
	uri += queryDelimiter
	//url := url.URL{
	//	RawPath:uri,
	//}
	url, _ := url.Parse(uri)
	q := url.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	url.RawQuery = q.Encode()
	return url.String()
}
