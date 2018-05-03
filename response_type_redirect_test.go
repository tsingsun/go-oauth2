package oauth2_test

import (
	"testing"
	"github.com/tsingsun/go-oauth2"
)

func TestMakeRedirectUri(t *testing.T)  {
	uri := "http://localhost"
	parms:= map[string]string{
		"access_token":"abcefg",
		"token_type":"bear",
	}
	eUri := oauth2.MakeRedirectUri(uri,parms,"?")
	if eUri != "http://localhost?access_token=abcefg&token_type=bear" {
		t.Error("not correct uri")
	}
}
