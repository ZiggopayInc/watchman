// Package account lets a signed-in user change their own password. The sign-in step in front of Watchman
// (an ALB Cognito action) passes the user's Cognito access token to this server in a header; the browser
// never sees it, so the change has to be made here.
package account

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/moov-io/base/log"

	"github.com/gorilla/mux"
)

const accessTokenHeader = "x-amzn-oidc-accesstoken"

type PasswordController interface {
	AppendRoutes(router *mux.Router) *mux.Router
}

// NewPasswordController reads the Cognito region from COGNITO_REGION (default eu-north-1).
func NewPasswordController(logger log.Logger) PasswordController {
	region := os.Getenv("COGNITO_REGION")
	if region == "" {
		region = "eu-north-1"
	}
	return &passwordController{
		logger:   logger,
		endpoint: fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/", region),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

type passwordController struct {
	logger   log.Logger
	endpoint string
	client   *http.Client
}

type changePasswordRequest struct {
	PreviousPassword string `json:"previousPassword"`
	ProposedPassword string `json:"proposedPassword"`
}

func (c *passwordController) AppendRoutes(router *mux.Router) *mux.Router {
	router.
		Name("AccountPassword.v2").
		Methods("POST").
		Path("/v2/account/password").
		HandlerFunc(c.changePassword)
	return router
}

func (c *passwordController) changePassword(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get(accessTokenHeader)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "sign in again to change your password")
		return
	}

	var body changePasswordRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "send the current and new password")
		return
	}
	if body.PreviousPassword == "" || body.ProposedPassword == "" {
		writeError(w, http.StatusBadRequest, "the current and new password are both required")
		return
	}

	status, cognitoType, err := c.callCognito(r, token, body)
	if err != nil {
		c.logger.Error().LogErrorf("password change could not reach Cognito: %v", err)
		writeError(w, http.StatusBadGateway, "the password could not be changed right now, try again")
		return
	}
	switch cognitoType {
	case "":
		w.WriteHeader(http.StatusNoContent)
	case "NotAuthorizedException":
		writeError(w, http.StatusBadRequest, "the current password is not correct")
	case "InvalidPasswordException":
		writeError(w, http.StatusBadRequest, "the new password does not meet the password rules: at least 12 characters, with upper and lower case letters, numbers and symbols")
	case "LimitExceededException", "TooManyRequestsException":
		writeError(w, http.StatusTooManyRequests, "too many attempts, wait a few minutes and try again")
	default:
		c.logger.Error().Log(fmt.Sprintf("password change failed with Cognito status %d and error %s", status, cognitoType))
		writeError(w, http.StatusBadGateway, "the password could not be changed right now, try again")
	}
}

// callCognito makes the ChangePassword call with the user's own access token, so no AWS credentials are needed.
// It returns the Cognito error type, or an empty string on success.
func (c *passwordController) callCognito(r *http.Request, token string, body changePasswordRequest) (int, string, error) {
	payload, err := json.Marshal(map[string]string{
		"AccessToken":      token,
		"PreviousPassword": body.PreviousPassword,
		"ProposedPassword": body.ProposedPassword,
	})
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AWSCognitoIdentityProviderService.ChangePassword")

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return resp.StatusCode, "", nil
	}
	var failure struct {
		Type string `json:"__type"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&failure)
	return resp.StatusCode, failure.Type, nil
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
