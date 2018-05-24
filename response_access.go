package oauth2

type AccessTokenResponse struct {
	UserID       string `json:"user_id,omitempty"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int32  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Error        error  `json:"-"`
}
