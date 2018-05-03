package oauth2_test

import (
	"testing"
	"github.com/golang/mock/gomock"
	"github.com/tsingsun/go-oauth2"
	mocks "github.com/tsingsun/go-oauth2/mocks"
	"time"
	"strings"
	"github.com/tsingsun/go-oauth2/errors"
	"encoding/json"
)

const (
	DEFAULT_SCOPE  = "basic"
	CODE_VERIFIER  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestAuthCodeGrant_GetIdentifier(t *testing.T) {
	grant := &oauth2.AuthCodeGrant{
	}
	if grant.GetIdentifier() != "authorization_code" {
		t.Error()
	}
}

func TestAuthCodeGrant_CanRespondToAuthorizationRequest(t *testing.T) {
	grant := &oauth2.AuthCodeGrant{}

	request := &oauth2.RequestWapper{
		ResponseType: "code",
		ClientId:     "foo",
	}
	if err := grant.CanRespondToAuthorizationRequest(request); err != nil {
		t.Error(err.Error())
	}
}

func TestAuthCodeGrant_ValidateAuthorizationRequest(t *testing.T) {
	client := &oauth2.ClientEntity{
		RedirectUri: []string{"http://foo/bar"},
	}
	mockCtl := gomock.NewController(t)
	clientRep := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRep.EXPECT().GetClientEntity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(client)
	scope := &Scope{}
	scopeRep := mocks.NewMockScopeRepositoryInterface(mockCtl)
	scopeRep.EXPECT().GetScopeEntityByIdentifier(nil).Return(scope)

	grant := &oauth2.AuthCodeGrant{
		AuthCodeRepository:     mocks.NewMockAuthCodeRepositoryInterface(mockCtl),
		RefreshTokenRepository: mocks.NewMockRefreshTokenRepositoryInterface(mockCtl),
		AuthCodeTTL:            10 * time.Minute,
	}

	grant.SetClientRepository(clientRep)
	grant.SetScopeRepository(scopeRep)
	grant.SetDefaultScope(DEFAULT_SCOPE)
	rq := &oauth2.RequestWapper{
		ResponseType: "code",
		ClientId:     "foo",
		RedirectUri:  "http://foo/bar",
	}
	ar, err := grant.ValidateAuthorizationRequest(rq)
	if err != nil || ar == nil {
		t.Error(err.Error())
	}
}

func TestAuthCodeGrant_ValidateAuthorizationRequestCodeChallenge(t *testing.T) {
	client := &oauth2.ClientEntity{
		RedirectUri: []string{"http://foo/bar"},
	}
	mockCtl := gomock.NewController(t)
	clientRep := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRep.EXPECT().GetClientEntity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(client)
	scope := &Scope{}
	scopeRep := mocks.NewMockScopeRepositoryInterface(mockCtl)
	scopeRep.EXPECT().GetScopeEntityByIdentifier(nil).Return(scope)

	grant := &oauth2.AuthCodeGrant{
		AuthCodeRepository:     mocks.NewMockAuthCodeRepositoryInterface(mockCtl),
		RefreshTokenRepository: mocks.NewMockRefreshTokenRepositoryInterface(mockCtl),
		AuthCodeTTL:            10 * time.Minute,
	}
	grant.EnableCodeExchangeProof()
	grant.SetClientRepository(clientRep)
	grant.SetScopeRepository(scopeRep)
	grant.SetDefaultScope(DEFAULT_SCOPE)
	rq := &oauth2.RequestWapper{
		ResponseType:        "code",
		ClientId:            "foo",
		RedirectUri:         "http://foo/bar",
		CodeChallenge:       CODE_CHALLENGE,
		CodeChallengeMethod: "plain",
	}
	ar, err := grant.ValidateAuthorizationRequest(rq)
	if err != nil || ar == nil {
		t.Error(err.Error())
	}
}

func TestAuthCodeGrant_ValidateAuthorizationRequestCodeChallengeInvalidLengthTooShort(t *testing.T) {
	client := &oauth2.ClientEntity{
		RedirectUri: []string{"http://foo/bar"},
	}
	mockCtl := gomock.NewController(t)
	clientRep := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRep.EXPECT().GetClientEntity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(client)
	scope := &Scope{}
	scopeRep := mocks.NewMockScopeRepositoryInterface(mockCtl)
	scopeRep.EXPECT().GetScopeEntityByIdentifier(nil).Return(scope)

	grant := &oauth2.AuthCodeGrant{
		AuthCodeRepository:     mocks.NewMockAuthCodeRepositoryInterface(mockCtl),
		RefreshTokenRepository: mocks.NewMockRefreshTokenRepositoryInterface(mockCtl),
		AuthCodeTTL:            10 * time.Minute,
	}
	grant.EnableCodeExchangeProof()
	grant.SetClientRepository(clientRep)
	grant.SetScopeRepository(scopeRep)
	grant.SetDefaultScope(DEFAULT_SCOPE)
	rq := &oauth2.RequestWapper{
		ResponseType:        "code",
		ClientId:            "foo",
		RedirectUri:         "http://foo/bar",
		CodeChallenge:       strings.Repeat("A", 42),
		CodeChallengeMethod: "plain",
	}
	ar, err := grant.ValidateAuthorizationRequest(rq)
	if err != nil || ar != nil {
		if err != errors.ErrInvalidCodeChallenge {
			t.Error(err.Error())
		}
	}
}

func TestAuthCodeGrant_ValidateAuthorizationRequestCodeChallengeInvalidLengthTooLong(t *testing.T) {
	client := &oauth2.ClientEntity{
		RedirectUri: []string{"http://foo/bar"},
	}
	mockCtl := gomock.NewController(t)
	clientRep := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRep.EXPECT().GetClientEntity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(client)
	scope := &Scope{}
	scopeRep := mocks.NewMockScopeRepositoryInterface(mockCtl)
	scopeRep.EXPECT().GetScopeEntityByIdentifier(nil).Return(scope)

	grant := &oauth2.AuthCodeGrant{
		AuthCodeRepository:     mocks.NewMockAuthCodeRepositoryInterface(mockCtl),
		RefreshTokenRepository: mocks.NewMockRefreshTokenRepositoryInterface(mockCtl),
		AuthCodeTTL:            10 * time.Minute,
	}
	grant.EnableCodeExchangeProof()
	grant.SetClientRepository(clientRep)
	grant.SetScopeRepository(scopeRep)
	grant.SetDefaultScope(DEFAULT_SCOPE)
	rq := &oauth2.RequestWapper{
		ResponseType:        "code",
		ClientId:            "foo",
		RedirectUri:         "http://foo/bar",
		CodeChallenge:       strings.Repeat("A", 129),
		CodeChallengeMethod: "plain",
	}
	ar, err := grant.ValidateAuthorizationRequest(rq)
	if err != nil || ar != nil {
		if err != errors.ErrInvalidCodeChallenge {
			t.Error(err.Error())
		}
	}
}

func TestAuthCodeGrant_ValidateAuthorizationRequestInvalidCodeChallengeMethod(t *testing.T) {
	client := &oauth2.ClientEntity{
		RedirectUri: []string{"http://foo/bar"},
	}
	mockCtl := gomock.NewController(t)
	clientRep := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRep.EXPECT().GetClientEntity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(client)
	scope := &Scope{}
	scopeRep := mocks.NewMockScopeRepositoryInterface(mockCtl)
	scopeRep.EXPECT().GetScopeEntityByIdentifier(nil).Return(scope)

	grant := &oauth2.AuthCodeGrant{
		AuthCodeRepository:     mocks.NewMockAuthCodeRepositoryInterface(mockCtl),
		RefreshTokenRepository: mocks.NewMockRefreshTokenRepositoryInterface(mockCtl),
		AuthCodeTTL:            10 * time.Minute,
	}
	grant.EnableCodeExchangeProof()
	grant.SetClientRepository(clientRep)
	grant.SetScopeRepository(scopeRep)
	grant.SetDefaultScope(DEFAULT_SCOPE)
	rq := &oauth2.RequestWapper{
		ResponseType:        "code",
		ClientId:            "foo",
		RedirectUri:         "http://foo/bar",
		CodeChallenge:       strings.Repeat("A", 43),
		CodeChallengeMethod: "foo",
	}
	ar, err := grant.ValidateAuthorizationRequest(rq)
	if err != nil || ar != nil {
		if err != errors.ErrInvalidCodeChallengeMethod {
			t.Error(err.Error())
		}
	}
}

func TestAuthCodeGrant_ValidateAuthorizationRequestCodeChallengeInvalidCharacters(t *testing.T) {
	client := &oauth2.ClientEntity{
		RedirectUri: []string{"http://foo/bar"},
	}
	mockCtl := gomock.NewController(t)
	clientRep := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRep.EXPECT().GetClientEntity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(client)
	scope := &Scope{}
	scopeRep := mocks.NewMockScopeRepositoryInterface(mockCtl)
	scopeRep.EXPECT().GetScopeEntityByIdentifier(nil).Return(scope)

	grant := &oauth2.AuthCodeGrant{
		AuthCodeRepository:     mocks.NewMockAuthCodeRepositoryInterface(mockCtl),
		RefreshTokenRepository: mocks.NewMockRefreshTokenRepositoryInterface(mockCtl),
		AuthCodeTTL:            10 * time.Minute,
	}
	grant.EnableCodeExchangeProof()
	grant.SetClientRepository(clientRep)
	grant.SetScopeRepository(scopeRep)
	grant.SetDefaultScope(DEFAULT_SCOPE)
	rq := &oauth2.RequestWapper{
		ResponseType:        "code",
		ClientId:            "foo",
		RedirectUri:         "http://foo/bar",
		CodeChallenge:       strings.Repeat("A", 43) + "!",
		CodeChallengeMethod: "plain",
	}
	ar, err := grant.ValidateAuthorizationRequest(rq)
	if err != nil || ar != nil {
		if err != errors.ErrInvalidCodeChallenge {
			t.Error(err.Error())
		}
	}
}

func TestAuthCodeGrant_ValidateAuthorizationRequestInvalidClientId(t *testing.T) {
	mockCtl := gomock.NewController(t)
	clientRep := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRep.EXPECT().GetClientEntity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	grant := &oauth2.AuthCodeGrant{
		AuthCodeRepository:     mocks.NewMockAuthCodeRepositoryInterface(mockCtl),
		RefreshTokenRepository: mocks.NewMockRefreshTokenRepositoryInterface(mockCtl),
		AuthCodeTTL:            10 * time.Minute,
	}
	grant.SetClientRepository(clientRep)
	rq := &oauth2.RequestWapper{
		ResponseType: "code",
		ClientId:     "foo",
	}
	ar, err := grant.ValidateAuthorizationRequest(rq)
	if err != nil || ar != nil {
		if err != errors.ErrInvalidClient {
			t.Error(err.Error())
		}
	}
}

func TestAuthCodeGrant_ValidateAuthorizationRequestBadRedirectUriArray(t *testing.T) {
	client := &oauth2.ClientEntity{
		RedirectUri: []string{"http://foo/bar"},
	}
	mockCtl := gomock.NewController(t)
	clientRep := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRep.EXPECT().GetClientEntity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(client)
	scope := &Scope{}
	scopeRep := mocks.NewMockScopeRepositoryInterface(mockCtl)
	scopeRep.EXPECT().GetScopeEntityByIdentifier(nil).Return(scope)

	grant := &oauth2.AuthCodeGrant{
		AuthCodeRepository:     mocks.NewMockAuthCodeRepositoryInterface(mockCtl),
		RefreshTokenRepository: mocks.NewMockRefreshTokenRepositoryInterface(mockCtl),
		AuthCodeTTL:            10 * time.Minute,
	}
	grant.EnableCodeExchangeProof()
	grant.SetClientRepository(clientRep)
	grant.SetScopeRepository(scopeRep)
	grant.SetDefaultScope(DEFAULT_SCOPE)
	rq := &oauth2.RequestWapper{
		ResponseType: "code",
		ClientId:     "foo",
		RedirectUri:  "http://bar",
	}
	ar, err := grant.ValidateAuthorizationRequest(rq)
	if err != nil || ar != nil {
		if err != errors.ErrInvalidRedirectUri {
			t.Error(err.Error())
		}
	}
}

func TestAuthCodeGrant_CompleteAuthorizationRequest(t *testing.T) {
	authReqest := &oauth2.AuthorizationRequest{
		Client:                  new(oauth2.ClientEntity),
		GrantType:               oauth2.AuthCodeGrantType,
		User:                    new(User),
		IsAuthorizationApproved: true,
	}
	mockCtl := gomock.NewController(t)
	authcodeRep := mocks.NewMockAuthCodeRepositoryInterface(mockCtl)
	authcode := new(AuthCode)
	authcodeRep.EXPECT().GetNewAuthCode().Return(authcode)
	authcodeRep.EXPECT().PersistNewAuthCode(gomock.Any()).Return(true)
	grant := &oauth2.AuthCodeGrant{
		AuthCodeRepository:     authcodeRep,
		RefreshTokenRepository: mocks.NewMockRefreshTokenRepositoryInterface(mockCtl),
		AuthCodeTTL:            10 * time.Minute,
	}
	grant.SetEncryptionKey(ENCRYPTION_KEY)
	_, err := grant.CompleteAuthorizationRequest(authReqest)
	if err != nil {
		t.Error(err.Error())
	}
}

func mockAccessTokenGrant(t *testing.T) *oauth2.AuthCodeGrant {
	client := &oauth2.ClientEntity{
		RedirectUri: []string{"http://foo/bar"},
	}
	client.SetIdentifier("foo")
	mockCtl := gomock.NewController(t)
	clientRep := mocks.NewMockClientRepositoryInterface(mockCtl)
	clientRep.EXPECT().GetClientEntity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(client)

	scopeEntity := &Scope{}
	scopeRep := mocks.NewMockScopeRepositoryInterface(mockCtl)
	scopeRep.EXPECT().GetScopeEntityByIdentifier(gomock.Any()).Return(scopeEntity)
	scopeRep.EXPECT().FinalizeScopes(gomock.Any(), gomock.Any(), client, gomock.Any(), ).Return([]oauth2.ScopeEntityInterface{scopeEntity})

	accessRep := mocks.NewMockAccessTokenRepositoryInterface(mockCtl)
	accessRep.EXPECT().GetNewToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(new(AccessToken))
	accessRep.EXPECT().PersistNewAccessToken(gomock.Any()).Return(true)

	refreshRep := mocks.NewMockRefreshTokenRepositoryInterface(mockCtl)
	refreshRep.EXPECT().PersistNewRefreshToken(gomock.Any()).Return(true)
	refreshRep.EXPECT().GetNewRefreshToken().Return(new(oauth2.RefreshTokenEntity))

	authcodeRep := mocks.NewMockAuthCodeRepositoryInterface(mockCtl)
	authcodeRep.EXPECT().IsAuthCodeRevoked(gomock.Any()).Return(false)
	authcodeRep.EXPECT().RevokeAuthCode(gomock.Any())

	grant := &oauth2.AuthCodeGrant{
		AuthCodeRepository:     authcodeRep,
		RefreshTokenRepository: refreshRep,
		AuthCodeTTL:            10 * time.Minute,
	}
	grant.GrantTypeInterface = grant
	grant.SetClientRepository(clientRep)
	grant.SetScopeRepository(scopeRep)
	grant.SetAccessTokenRepository(accessRep)
	grant.SetEncryptionKey(ENCRYPTION_KEY)
	return grant
}

func TestAuthCodeGrant_RespondToAccessTokenRequest(t *testing.T) {
	grant := mockAccessTokenGrant(t)
	code := oauth2.AuthCodePayload{
		AuthCodeId:  "00001",
		ExpiresTime: time.Now().Add(3600 * time.Second),
		ClientId:    "foo",
		UserID:      "123",
		Scopes:      "foo",
		RedirectUri: "http://foo/bar",
	}
	jcode, _ := json.Marshal(code)
	ecode, e := grant.Encrypt(jcode)
	if e != nil {
		panic(e)
	}
	request := &oauth2.RequestWapper{
		GrantType:   oauth2.AuthCodeGrantType,
		ClientId:    "foo",
		RedirectUri: "http://foo/bar",
		Code:        ecode,
	}
	bearer := &oauth2.BearerTokenResponse{}
	err := grant.RespondToAccessTokenRequest(request, bearer)
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
