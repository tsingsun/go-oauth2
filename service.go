package oauth2

import (
	"github.com/tsingsun/go-oauth2/errors"
	"reflect"
	"net/http"
	"encoding/json"
)

type Option func(*Options)

type GetUser func(*http.Request) (UserEntityInterface, error)

type Service struct {
	opts       Options
	GrantTypes map[GrantType]GrantTypeInterface
	GetUser    GetUser
}

func NewService(opts ...Option) *Service {
	options := NewOptions(opts...)

	return &Service{
		opts:       options,
		GrantTypes: make(map[GrantType]GrantTypeInterface),
	}
}

func (s *Service) Options() *Options {
	return &s.opts
}

func (s *Service) RegisterGrantType(gti GrantTypeInterface) {
	s.GrantTypes[gti.GetIdentifier()] = gti
}

func (s *Service) ClientRepository() ClientRepositoryInterface {
	return s.opts.ClientRepository
}

func (s *Service) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	tq := TokenRequestFromHttp(r)
	ret, err := s.HandleAccessTokenRequestInternal(tq)
	if err != nil {
		errorResponse(err,w,r)
		return
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(ret)
	return
}

func (s *Service) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	ar, err := s.ValidateAuthorizationRequest(w, r)
	if err != nil {
		errorResponse(err,w,r)
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.GetUser != nil {
		ar.User, err = s.GetUser(r)
	}
	if err != nil {
		errorResponse(err,w,r)
		return
	}
	ar.IsAuthorizationApproved = true
	rts, err := s.CompleteAuthorizationRequest(ar)
	if err != nil {
		errorResponse(err,w,r)
		return
	}
	rts.GenerateHttpResponse(w)
}

func (s *Service) HandleAccessTokenRequestInternal(req *RequestWapper) (*AccessTokenResponse, error) {
	handle, ok := s.GrantTypes[req.GrantType]
	if !ok {
		return nil, errors.ErrInvalidGrant
	}
	if err := handle.CanRespondToAccessTokenRequest(req); err != nil {
		return nil, err
	}
	rt := s.createResponseType()
	if err := handle.RespondToAccessTokenRequest(req, rt); err != nil {
		return nil, err
	}
	return rt.GenerateResponse(), nil
}

func (s *Service) ValidateAuthorizationRequest(w http.ResponseWriter, r *http.Request) (ar *AuthorizationRequest, err error) {
	tq := AuthorizeRequestFromHttp(r)
	handle, ok := s.GrantTypes[tq.GrantType]
	if !ok {
		return nil, errors.ErrInvalidGrant
	}
	if err = handle.CanRespondToAuthorizationRequest(tq); err != nil {
		return
	}
	ar, err = handle.ValidateAuthorizationRequest(tq)
	if err != nil {
		return
	}
	return
}

func (s *Service) CompleteAuthorizationRequest(ar *AuthorizationRequest) (rtr *RedirectTypeResponse, err error) {
	handle := s.GrantTypes[ar.GrantType]
	rtr, err = handle.CompleteAuthorizationRequest(ar)
	return
}

func (s *Service) createResponseType() ResponseTypeInterface {
	rtIns := s.Options().DefaultResponseType
	rtType := reflect.TypeOf(rtIns)
	ptr := reflect.New(rtType.Elem())
	ret := ptr.Interface().(ResponseTypeInterface)
	return ret
}

func errorResponse(err error, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(500)
	desc, ok := errors.Descriptions[err]
	if !ok {
		desc = http.StatusText(500)
	}
	eData := map[string]string{
		"error":             err.Error(),
		"error_description": desc,
		"error_uri":         "",
	}
	if state := r.Form.Get("state"); state != "" {
		eData["state"] = state
	}
	json.NewEncoder(w).Encode(eData)
}
