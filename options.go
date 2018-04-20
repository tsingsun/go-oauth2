package oauth2

type Options struct {
	PrivateKey             string
	PublickKey             string
	EncryptionKey          string
	ClientRepository       ClientRepositoryInterface
	AccessTokenRepository  AccessTokenRepositoryInterface
	ScopeRepository        ScopeRepositoryInterface
	AuthCodeRepository     AuthCodeRepositoryInterface
	RefreshTokenRepository RefreshTokenRepositoryInterface
	GrantTypes             map[GrantType]GrantTypeInterface
	DefaultResponseType    ResponseTypeInterface
}

func NewOptions(opts ...Option) Options {
	opt := Options{}
	opt.GrantTypes = make(map[GrantType]GrantTypeInterface)
	for _, o := range opts {
		o(&opt)
	}
	if opt.DefaultResponseType == nil {
		opt.DefaultResponseType = new(BearerTokenResponse)
	}
	return opt
}

func SetEncryptionKey(p string) Option {
	return func(options *Options) {
		options.EncryptionKey = p
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

func SetGrantTypes(gts ...GrantTypeInterface) Option {
	return func(options *Options) {
		for _, o := range gts {
			options.GrantTypes[o.GetIdentifier()] = o
		}
	}
}

func SetResponseType(r ResponseTypeInterface) Option {
	return func(options *Options) {
		options.DefaultResponseType = r
	}
}
