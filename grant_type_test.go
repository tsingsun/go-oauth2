package oauth2_test

import (
	"github.com/tsingsun/go-oauth2"
	"testing"
)

func TestGenerateUniqueIdentifier(t *testing.T) {
	gt := oauth2.Grant{}
	t.Error(gt.GenerateUniqueIdentifier(40))
}
