package oauth2_test

import (
	"testing"
	"github.com/tsingsun/go-oauth2"
)

func TestGenerateUniqueIdentifier(t *testing.T) {
	gt := oauth2.Grant{}
	t.Error(gt.GenerateUniqueIdentifier(40))
}
