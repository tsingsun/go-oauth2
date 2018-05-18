package oauth2_test

import (
	"testing"
	"github.com/golang/mock/gomock"
	mocks "github.com/tsingsun/go-oauth2/mocks"
	"github.com/tsingsun/go-oauth2"
	"time"
	"encoding/json"
)

func TestRefreshTokenGrant_RespondToAccessTokenRequest(t *testing.T) {
	client := &Client{}
	client.SetIdentifier("foo")
	mockCtl := gomock.NewController(t)
	clientRepositoryMock := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRepositoryMock.EXPECT().GetClientEntity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(client)

	scope := &Scope{}
	scope.SetIdentifier("foo")
	scopeRepositoryMock := mocks.NewMockScopeRepositoryInterface(mockCtl)
	scopeRepositoryMock.EXPECT().GetScopeEntityByIdentifier(gomock.Any()).Return(scope)

	accessTokenRepositoryMock := mocks.NewMockAccessTokenRepositoryInterface(mockCtl)
	accessTokenRepositoryMock.EXPECT().GetNewToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(&AccessToken{})

	refreshTokenRepositoryMock := mocks.NewMockRefreshTokenRepositoryInterface(mockCtl)
	refreshTokenRepositoryMock.EXPECT().GetNewRefreshToken().Return(&RefreshToken{})
	grant := oauth2.RefreshTokenGrant{
		RefreshTokenRepository: refreshTokenRepositoryMock,
	}
	grant.SetClientRepository(clientRepositoryMock)
	grant.SetScopeRepository(scopeRepositoryMock)
	grant.SetAccessTokenRepository(accessTokenRepositoryMock)
	grant.SetEncryptionKey(ENCRYPTION_KEY)
	payload := oauth2.RefreshTokenPayload{
		ClientId:       "foo",
		RefreshTokenId: "abcdefg",
		AccessTokenId:  "gfedcba",
		Scopes:         "foo",
		UserID:         "123",
		ExpiresTime:    time.Now().Add(10 * time.Minute),
	}
	d,_ := json.Marshal(payload)
	oldRefreshToken,_ := grant.Encrypt(d)

	var sw = &oauth2.RequestWapper{
		ClientId:"foo",
		ClientSecret:"bar",
		RefreshToken:oldRefreshToken,
		Scope:"foo",
	}
	bearer := &oauth2.BearerTokenResponse{}
	grant.RespondToAccessTokenRequest(sw,bearer)
	var err error
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bearer.AccessToken.(oauth2.AccessTokenEntityInterface); !ok {
		t.Error("access token error")
	}

	if _, ok := bearer.RefreshToken.(oauth2.RefreshTokenEntityInterface); !ok {
		t.Error("refresh token error")
	}
}
