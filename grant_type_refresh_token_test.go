package oauth2_test

import (
	"context"
	"encoding/json"
	"github.com/golang/mock/gomock"
	"github.com/tsingsun/go-oauth2"
	mocks "github.com/tsingsun/go-oauth2/mocks"
	"testing"
	"time"
)

func TestRefreshTokenGrant_RespondToAccessTokenRequest(t *testing.T) {
	ctx := context.Background()
	client := &Client{}
	client.SetIdentifier("foo")
	mockCtl := gomock.NewController(t)
	clientRepositoryMock := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRepositoryMock.EXPECT().GetClientEntity(gomock.Any(),gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(client)

	scope := &Scope{}
	scope.SetIdentifier("foo")
	scopeRepositoryMock := mocks.NewMockScopeRepositoryInterface(mockCtl)
	scopeRepositoryMock.EXPECT().GetScopeEntityByIdentifier(gomock.Any(),gomock.Any()).Return(scope)

	accessTokenRepositoryMock := mocks.NewMockAccessTokenRepositoryInterface(mockCtl)
	accessTokenRepositoryMock.EXPECT().GetNewToken(gomock.Any(),gomock.Any(), gomock.Any(), gomock.Any()).Return(&AccessToken{})
	accessTokenRepositoryMock.EXPECT().RevokeAccessToken(gomock.Any(),gomock.Any()).Return()
	accessTokenRepositoryMock.EXPECT().PersistNewAccessToken(gomock.Any(),gomock.Any()).Return(true)

	refreshTokenRepositoryMock := mocks.NewMockRefreshTokenRepositoryInterface(mockCtl)
	refreshTokenRepositoryMock.EXPECT().GetNewRefreshToken(gomock.Any()).Return(&RefreshToken{})
	refreshTokenRepositoryMock.EXPECT().IsRefreshTokenRevoked(gomock.Any(),gomock.Any()).Return(false)
	refreshTokenRepositoryMock.EXPECT().RevokeRefreshToken(gomock.Any(),gomock.Any()).Return()
	refreshTokenRepositoryMock.EXPECT().PersistNewRefreshToken(gomock.Any(),gomock.Any()).Return(true)
	grant := oauth2.RefreshTokenGrant{
		RefreshTokenRepository: refreshTokenRepositoryMock,
	}
	grant.SetClientRepository(clientRepositoryMock)
	grant.SetScopeRepository(scopeRepositoryMock)
	grant.SetAccessTokenRepository(accessTokenRepositoryMock)
	grant.SetEncryptionKey([]byte(ENCRYPTION_KEY))
	payload := oauth2.RefreshTokenPayload{
		ClientId:       "foo",
		RefreshTokenId: "abcdefg",
		AccessTokenId:  "gfedcba",
		Scopes:         "foo",
		UserID:         "123",
		ExpiresTime:    time.Now().Add(10 * time.Minute),
	}
	d, _ := json.Marshal(payload)
	oldRefreshToken, _ := grant.Encrypt(d)

	var sw = &oauth2.RequestWapper{
		ClientId:     "foo",
		ClientSecret: "bar",
		RefreshToken: oldRefreshToken,
		Scope:        "foo",
	}
	sw.SetContext(ctx)

	bearer := &oauth2.BearerTokenResponse{}
	err := grant.RespondToAccessTokenRequest(sw, bearer)
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
