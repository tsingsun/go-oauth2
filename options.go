package oauth2

import (
	"crypto/rsa"
	"crypto/x509"
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
//
func WithPrivateKey(content []byte) Option {
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

func WithPublicKey(content []byte) Option {
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
func WithEncryptionKey(p string) Option {
	return func(options *Options) {
		options.EncryptionKey = []byte(p)
	}
}

func WithClientRepository(c ClientRepositoryInterface) Option {
	return func(options *Options) {
		options.ClientRepository = c
	}
}

func WithAccessTokenRepository(a AccessTokenRepositoryInterface) Option {
	return func(options *Options) {
		options.AccessTokenRepository = a
	}
}

func WithScopeRepository(s ScopeRepositoryInterface) Option {
	return func(options *Options) {
		options.ScopeRepository = s
	}
}

func WithResponseType(r ResponseTypeInterface) Option {
	return func(options *Options) {
		options.DefaultResponseType = r
	}
}

func WithAuthCodeRepository(ac AuthCodeRepositoryInterface) Option {
	return func(options *Options) {
		options.AuthCodeRepository = ac
	}
}

func WithRefreshTokenRepository(rt RefreshTokenRepositoryInterface) Option {
	return func(options *Options) {
		options.RefreshTokenRepository = rt
	}
}