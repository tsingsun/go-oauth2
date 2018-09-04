package oauth2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
)

type Options struct {
	PrivateKey             *rsa.PrivateKey
	PublickKey             *rsa.PublicKey
	EncryptionKey          []byte
	ClientRepository       ClientRepositoryInterface
	AccessTokenRepository  AccessTokenRepositoryInterface
	ScopeRepository        ScopeRepositoryInterface
	AuthCodeRepository     AuthCodeRepositoryInterface
	RefreshTokenRepository RefreshTokenRepositoryInterface
	DefaultResponseType    ResponseTypeInterface
}

func NewOptions(opts ...Option) *Options {
	opt := &Options{}
	for _, o := range opts {
		o(opt)
	}
	if opt.DefaultResponseType == nil {
		opt.DefaultResponseType = new(BearerTokenResponse)
	}
	return opt
}

func SetPrivateKey(content []byte) Option {
	block, _ := pem.Decode(content)
	if block == nil {
		panic(errors.New("private key error"))
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	pri, ok := priv.(*rsa.PrivateKey)
	if !ok {
		panic(errors.New("private key error"))
	}
	return func(options *Options) {
		options.PrivateKey = pri
	}
}

func SetPublicKey(content []byte) Option {
	block, _ := pem.Decode(content)
	if block == nil {
		panic(errors.New("private key error"))
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		panic(errors.New("private key error"))
	}
	return func(options *Options) {
		options.PublickKey = pub
	}
}
func SetEncryptionKey(p string) Option {
	return func(options *Options) {
		options.EncryptionKey = []byte(p)
	}
}

func SetClientRepository(c ClientRepositoryInterface) Option {
	return func(options *Options) {
		options.ClientRepository = c
	}
}

func SetAccessTokenRepository(a AccessTokenRepositoryInterface) Option {
	return func(options *Options) {
		options.AccessTokenRepository = a
	}
}

func SetScopeRepository(s ScopeRepositoryInterface) Option {
	return func(options *Options) {
		options.ScopeRepository = s
	}
}

func SetResponseType(r ResponseTypeInterface) Option {
	return func(options *Options) {
		options.DefaultResponseType = r
	}
}

func SetAuthCodeRepository(ac AuthCodeRepositoryInterface) Option {
	return func(options *Options) {
		options.AuthCodeRepository = ac
	}
}

func SetRefreshTokenRepository(rt RefreshTokenRepositoryInterface) Option {
	return func(options *Options) {
		options.RefreshTokenRepository = rt
	}
}

// MarshalPKCS8PrivateKey 私钥解析
func marshalPKCS8PrivateKey(key *rsa.PrivateKey) []byte {

	info := struct {
		Version             int
		PrivateKeyAlgorithm []asn1.ObjectIdentifier
		PrivateKey          []byte
	}{}

	info.Version = 0
	info.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	info.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	info.PrivateKey = x509.MarshalPKCS1PrivateKey(key)
	k, _ := asn1.Marshal(info)
	return k

}
