package main

import (
	"net/http"
	"log"
	"github.com/tsingsun/go-oauth2"
	"github.com/tsingsun/go-oauth2/example/models"
	"time"
)

func main() {

	svr := oauth2.NewService(
		oauth2.SetClientRepository(&models.ClientRepository{}),
		oauth2.SetAccessTokenRepository(&models.AccessToken{}),
		oauth2.SetResponseType(&oauth2.BearerTokenResponse{}),
		oauth2.SetScopeRepository(&models.Scope{}),
		oauth2.SetEncryptionKey("cxPrjjamV6wI82ka3YDWJ6PydkZU2opzwRRvEEogGVo="),
	)
	accessTokenTTL := 2 * time.Hour
	clientCredentials := oauth2.NewClientCredentialsGrant(svr.Options())
	clientCredentials.SetAccessTokenTTL(accessTokenTTL)
	svr.RegisterGrantType(clientCredentials)

	implicitGrant := oauth2.NewImplicitGrant(svr.Options())
	implicitGrant.SetAccessTokenTTL(1 * time.Hour)
	svr.RegisterGrantType(implicitGrant)

	authCodeGrant := oauth2.NewAuthCodeGrant(svr.Options())
	authCodeGrant.SetAuthCodeTTL(10 * time.Minute)
	authCodeGrant.SetAccessTokenTTL(1 * time.Hour)
	svr.RegisterGrantType(authCodeGrant)

	http.HandleFunc("/oauth2/v1/token", func(writer http.ResponseWriter, request *http.Request) {
		svr.HandleTokenRequest(writer, request)
	})
	http.HandleFunc("oauth2/v1/authorize", func(writer http.ResponseWriter, request *http.Request) {
		ar, err := svr.ValidateAuthorizationRequest(writer, request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		ar.User = new(models.User)
		ar.IsAuthorizationApproved = true
		rts, err := svr.CompleteAuthorizationRequest(ar)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		rts.GenerateHttpResponse(writer)
	})

	log.Println("Oauth Server is running at 9096 port.")
	log.Fatal(http.ListenAndServe(":9096", nil))
}
