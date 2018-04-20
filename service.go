package oauth2

import (
	"github.com/tsingsun/go-oauth2/errors"
)

type Option func(*Options)

type Service struct {
	opts Options
}

func NewService(opts ...Option) *Service {
	options := NewOptions(opts...)

	return &Service{
		opts: options,
	}
}

func (s *Service) Options() Options {
	return s.opts
}

func (s *Service) ClientRepository() ClientRepositoryInterface {
	return s.opts.ClientRepository
}

//func (s *Service) HandleAccessTokenRequest(w http.ResponseWriter, r *http.Request) AccessTokenEntityInterface {
//	handle := s.opts.GrantTypes[grantType]
//	return handle.GrantAccessTokenRequest(duration)
//}

func (s *Service) HandleAccessTokenRequest(req TokenRequest) (*AccessTokenResponse, error) {
	handle, ok := s.opts.GrantTypes[req.GrantType]
	if !ok {
		return nil, errors.NewInvalidGrant()
	}
	if err := handle.RespondToAccessTokenRequest(req, s.opts.DefaultResponseType); err != nil {
		return nil, err
	}
	return nil, nil
}
