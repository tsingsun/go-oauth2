package errors

import (
	"errors"
	"fmt"
)

func NewInvalidRequest(parameter string, hint string) error {

	if hint != "" {
		return errors.New(hint)
	} else {
		errorMessage := `The request is missing a required parameter, includes an invalid parameter value,includes a parameter more than once, or is otherwise malformed.`
		return errors.New(errorMessage + fmt.Sprintf("Check the `%s` parameter", parameter))
	}

}

func NewInvalidClient() error {
	errorMessage := "Client authentication failed"
	return errors.New(errorMessage)
}

func NewInvalidGrant() error {
	errorMessage := `The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token
                is invalid, expired, revoked, does not match the redirection URI used in the authorization request,
                or was issued to another client.`
	return errors.New(errorMessage)
}
