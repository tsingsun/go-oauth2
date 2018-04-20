package oauth2

import "time"

type RefreshTokenEntity struct {
	accessToken AccessTokenEntityInterface
	expiryDateTime time.Time
}

func (r *RefreshTokenEntity) SetAccessToken (accessToken AccessTokenEntityInterface)  {
	r.accessToken = accessToken
}

func (r *RefreshTokenEntity) GetAccessToken() AccessTokenEntityInterface {
	return r.accessToken
}

func (r *RefreshTokenEntity) GetExpiryDateTime() time.Time {
	return r.expiryDateTime
}

func (r *RefreshTokenEntity) SetExpiryDateTime(time time.Time)  {
	r.expiryDateTime = time
}




