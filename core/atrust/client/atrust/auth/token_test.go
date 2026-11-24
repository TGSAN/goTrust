package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/YangtseSu/goTrust/core/atrust/client/authchallenge"
	"github.com/pquerna/otp/totp"
)

func TestAuthStepFromTokenService(t *testing.T) {
	step := authStepFromData(authStepData{
		NextService: "auth/token",
		NextServiceList: []authServiceInfo{{
			AuthID:   "totp-id",
			AuthType: "auth/totp",
		}},
	})
	if step.Service != "auth/totp" || step.AuthID != "totp-id" {
		t.Fatalf("unexpected token step: %+v", step)
	}

	step = authStepFromData(authStepData{NextService: "auth/sendSms"})
	if step.Service != "auth/sms" || step.SMSMode != smsWithoutAuthID {
		t.Fatalf("unexpected sendSms step: %+v", step)
	}
}

func TestHTTPSTokenAuthChain(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprintf("skip=%t", skip), func(t *testing.T) {
			var tokenCalls int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/passport/v1/auth/authCheck":
					fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/token","nextServiceList":[{"authId":"https-id","authType":"auth/token","subType":"https"}]}}`)
				case "/passport/v1/auth/token":
					tokenCalls++
					if r.Method != http.MethodPost {
						t.Errorf("method = %s, want POST", r.Method)
					}
					var payload map[string]interface{}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					skipValue := "0"
					if skip {
						skipValue = "1"
					}
					want := map[string]interface{}{
						"code": "123456", "skipSecondaryAuth": skipValue,
						"taskId": "", "authId": "https-id",
					}
					if !reflect.DeepEqual(payload, want) {
						t.Errorf("payload = %#v, want %#v", payload, want)
					}
					fmt.Fprint(w, `{"code":0,"data":{"nextService":""}}`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			session := newTLSTestSession(server)
			session.challengeHandler = authchallenge.HandlerFuncs{
				Code: func(challenge authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
					if challenge.Kind != authchallenge.CodeTOTP || !challenge.CanSkipSecondaryAuth {
						t.Fatalf("unexpected challenge: %+v", challenge)
					}
					return authchallenge.CodeResponse{Code: "123456", SkipSecondaryAuth: skip}, nil
				},
			}
			if err := session.continueAuth(authStep{Service: "auth/authCheck"}); err != nil {
				t.Fatal(err)
			}
			if tokenCalls != 1 {
				t.Fatalf("token calls = %d, want 1", tokenCalls)
			}
		})
	}
}

func TestHTTPSTokenSavedSecret(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Code   string `json:"code"`
			AuthID string `json:"authId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.AuthID != "https-id" || !totp.Validate(payload.Code, secret) {
			t.Errorf("invalid HTTPS token request")
		}
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()
	session := newTLSTestSession(server)
	session.totpSecret = secret
	if _, err := session.completeHTTPSToken("https-id"); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSTokenRequiresAuthID(t *testing.T) {
	session := &Session{}
	if _, err := session.completeHTTPSToken(""); err == nil || !strings.Contains(err.Error(), "authId") {
		t.Fatalf("error = %v, want missing authId", err)
	}
}

func TestUnknownTokenSubtypeRemainsUnsupported(t *testing.T) {
	step := authStepFromData(authStepData{
		NextService: "auth/token",
		NextServiceList: []authServiceInfo{{
			AuthID: "id", AuthType: "auth/token", SubType: "unknown",
		}},
	})
	if step.Service != "auth/token" {
		t.Fatalf("unexpected token step: %+v", step)
	}
	if _, err := (&Session{}).runAuthStep(step); err == nil {
		t.Fatal("unknown token subtype unexpectedly accepted")
	}
}

func TestSubmitTOTPToken(t *testing.T) {
	type requestPayload struct {
		Username          string `json:"username"`
		Action            string `json:"action"`
		TOTPToken         string `json:"totpToken"`
		IsPrevEffect      bool   `json:"isPrevEffect"`
		SkipSecondaryAuth int    `json:"skipSecondaryAuth"`
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/passport/v1/auth/token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var payload requestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload.Username != "user@domain" || payload.Action != "auth" || payload.TOTPToken != "123456" || payload.IsPrevEffect || payload.SkipSecondaryAuth != 0 {
			t.Errorf("unexpected payload: %+v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/accessCheck"}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.username = "user@domain"
	step, err := session.submitToken(map[string]interface{}{
		"username":          session.username,
		"action":            "auth",
		"totpToken":         "123456",
		"isPrevEffect":      false,
		"skipSecondaryAuth": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "auth/accessCheck" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}

func TestCompleteTOTPUsesStructuredChallengeResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Token             string `json:"totpToken"`
			SkipSecondaryAuth int    `json:"skipSecondaryAuth"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload.Token != "123456" || payload.SkipSecondaryAuth != 1 {
			t.Errorf("unexpected payload: %+v", payload)
		}
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.challengeHandler = authchallenge.HandlerFuncs{
		Code: func(challenge authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
			if challenge.Kind != authchallenge.CodeTOTP || !challenge.CanSkipSecondaryAuth {
				t.Fatalf("unexpected challenge: %+v", challenge)
			}
			return authchallenge.CodeResponse{Code: "123456", SkipSecondaryAuth: true}, nil
		},
	}
	if _, err := session.completeTOTP(); err != nil {
		t.Fatal(err)
	}
}

func TestSubmitTokenAllowsSessionBoundIdentity(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if _, found := payload["username"]; found {
			t.Errorf("session-bound token request unexpectedly included username: %+v", payload)
		}
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	payload := map[string]interface{}{"totpToken": "123456"}
	session.addUsername(payload)
	if _, err := session.submitToken(payload); err != nil {
		t.Fatal(err)
	}
}

func TestSMSUsernameIsAvailableToTokenStep(t *testing.T) {
	session := &Session{}
	method := SMSLogin{Phone: "13800138000", Domain: "example"}
	session.username = smsUsername(method.Phone, method.Domain)

	payload := make(map[string]interface{})
	session.addUsername(payload)
	if got := payload["username"]; got != "13800138000@example" {
		t.Fatalf("SMS token username = %v, want 13800138000@example", got)
	}
}

func TestAccessCheck(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/passport/v1/auth/accessCheck" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	step, err := session.accessCheck()
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}
