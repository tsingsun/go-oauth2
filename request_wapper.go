package oauth2

import "net/http"

// the request parameters in OAuth request methods
type RequestWapper struct {
	// access_token
	GrantType    GrantType
	ClientId     string
	ClientSecret string
	// AuthorizationCode
	RedirectUri string
	Code        string
	// Proof Key
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
	// PasswordCredentials
	Scope        string
	Username     string
	Password     string
	RefreshToken string
	// implicit_type
	ResponseType string
	State        string
}

func TokenRequestFromHttp(r *http.Request) *RequestWapper {
	r.ParseForm()
	ret := new(RequestWapper)
	ret.GrantType = GrantType(r.Form.Get("grant_type"))
	ret.ClientId = r.Form.Get("client_id")
	ret.ClientSecret = r.Form.Get("client_secret")
	switch ret.GrantType {
	case AuthCodeGrantType:
		ret.Code = r.Form.Get("code")
		ret.RedirectUri = r.Form.Get("redirect_uri")
	case ClientCredentialGrantType:
		ret.Code = r.Form.Get("code")
	case PasswordGrantType:
		ret.Code = r.Form.Get("code")
		ret.Username = r.Form.Get("username")
		ret.Password = r.Form.Get("password")
	case RefreshTokenGrantType:
		ret.RefreshToken = r.Form.Get("refresh_token")
	}
	return ret

}

func AuthorizeRequestFromHttp(r *http.Request) *RequestWapper {
	r.ParseForm()
	ret := new(RequestWapper)
	ret.ClientId = r.Form.Get("client_id")
	ret.RedirectUri = r.Form.Get("redirect_uri")
	ret.Scope = r.Form.Get("scope")
	ret.ResponseType = r.Form.Get("response_type")
	ret.State = r.Form.Get("state")

	switch ret.ResponseType {
	case "token":
		ret.GrantType = ImplicitGrantType
	case "code":
		ret.GrantType = AuthCodeGrantType
		ret.CodeChallenge = r.Form.Get("code_challenge")
		ret.CodeChallengeMethod = r.Form.Get("code_challenge_method")
		if ret.CodeChallengeMethod == "" {
			ret.CodeChallengeMethod = "plain"
		}
	}
	return ret

}
