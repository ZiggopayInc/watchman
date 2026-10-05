package account

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moov-io/base/log"

	"github.com/gorilla/mux"
)

// fakeCognito answers ChangePassword the way Cognito does for the cases we handle.
func fakeCognito(t *testing.T, answer func(body map[string]string) (int, string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Amz-Target"); got != "AWSCognitoIdentityProviderService.ChangePassword" {
			t.Errorf("unexpected target %q", got)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		status, errType := answer(body)
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"__type":"` + errType + `"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
}

func router(endpoint string) *mux.Router {
	c := &passwordController{logger: log.NewNopLogger(), endpoint: endpoint, client: http.DefaultClient}
	return c.AppendRoutes(mux.NewRouter())
}

func post(t *testing.T, router *mux.Router, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v2/account/password", strings.NewReader(body))
	if token != "" {
		req.Header.Set("x-amzn-oidc-accesstoken", token)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestChangePasswordSucceeds(t *testing.T) {
	cognito := fakeCognito(t, func(body map[string]string) (int, string) {
		if body["AccessToken"] != "token-abc" || body["PreviousPassword"] != "Old-password-1" || body["ProposedPassword"] != "New-password-2" {
			t.Errorf("Cognito got the wrong fields: %v", body)
		}
		return http.StatusOK, ""
	})
	defer cognito.Close()

	rec := post(t, router(cognito.URL), "token-abc", `{"previousPassword":"Old-password-1","proposedPassword":"New-password-2"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestWrongCurrentPasswordIsReadable(t *testing.T) {
	cognito := fakeCognito(t, func(map[string]string) (int, string) {
		return http.StatusBadRequest, "NotAuthorizedException"
	})
	defer cognito.Close()

	rec := post(t, router(cognito.URL), "token-abc", `{"previousPassword":"wrong","proposedPassword":"New-password-2"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "current password is not correct") {
		t.Fatalf("want a clear 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMissingSignInIsRefused(t *testing.T) {
	rec := post(t, router("http://unused.invalid"), "", `{"previousPassword":"a","proposedPassword":"b"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without a token, got %d", rec.Code)
	}
}
