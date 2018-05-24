package oauth2_test

import (
	"github.com/tsingsun/go-oauth2"
	"testing"
)

func TestGenerateUniqueIdentifier(t *testing.T) {
	gt := oauth2.Grant{}
	want := gt.GenerateUniqueIdentifier(40)
	if len(want) != 40 {
		t.Error()
	}
}
