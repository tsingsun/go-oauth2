package oauth2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

type Crypt struct {
	encryptionKey []byte
}

func (c *Crypt) SetEncryptionKey(key []byte) {
	c.encryptionKey = key
}

func (c *Crypt) Encrypt(plainData []byte) (string, error) {
	data, err := c.aesEncrypt(plainData, c.encryptionKey)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(data), nil
}

func (c *Crypt) Decrypt(encrytData string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(encrytData)
	data, err = c.aesDecrypt(data, c.encryptionKey)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *Crypt) aesEncrypt(src []byte, key []byte) ([]byte, error) {
	var iv = key[:aes.BlockSize]
	encrypted := make([]byte, len(src))
	aesBlockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(encrypted, src)
	return encrypted, nil
}

func (c *Crypt) aesDecrypt(src []byte, key []byte) ([]byte, error) {
	var iv = key[:aes.BlockSize]
	decrypted := make([]byte, len(src))
	var aesBlockDecrypter cipher.Block
	aesBlockDecrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(decrypted, src)
	return decrypted, nil
}
