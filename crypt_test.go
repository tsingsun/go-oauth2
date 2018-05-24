package oauth2_test

import (
	"fmt"
	"github.com/tsingsun/go-oauth2"
	"strings"
	"testing"
)

func TestCrypt_Encrypt(t *testing.T) {
	crypt := oauth2.Crypt{}
	crypt.SetEncryptionKey([]byte(ENCRYPTION_KEY))
	plainText := strings.Repeat("A", 32)
	eData, err := crypt.Encrypt([]byte(plainText))
	if err != nil {
		t.Error(err)
	}
	fmt.Println(eData)
}

func TestCrypt_Decrypt(t *testing.T) {
	crypt := oauth2.Crypt{}
	crypt.SetEncryptionKey([]byte(ENCRYPTION_KEY))
	plainText := strings.Repeat("A", 32)
	eData, err := crypt.Encrypt([]byte(plainText))
	if err != nil {
		t.Error(err)
	}
	exp, err := crypt.Decrypt(eData)
	if err != nil {
		t.Error(err)
	}
	if string(exp) != strings.Repeat("A", 32) {
		t.Error("decrypt error")
	}
}
