package oauth2

import "net/http"

type BearerTokenResponse struct {
	ResponseType
}

func (b BearerTokenResponse) generateHttpResponse(response *http.Response) {

}
