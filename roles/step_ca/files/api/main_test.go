package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealth(t *testing.T) {
	a := &api{}
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()

	a.health(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected body: %s", response.Body.String())
	}
}

func TestAPIKeyAndLDAPAuthentication(t *testing.T) {
	a := &api{
		config: config{ldapUPNSuffix: "ice.land"},
		token:  "shared-token",
		authenticateLDAP: func(_ context.Context, username, password string) error {
			if username == "alice@ice.land" && password == "correct-password" {
				return nil
			}
			return errInvalidCredentials
		},
	}
	handler := a.authorize(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name       string
		apiKey     string
		username   string
		password   string
		wantStatus int
	}{
		{name: "missing API key", username: "alice", password: "correct-password", wantStatus: http.StatusUnauthorized},
		{name: "wrong API key", apiKey: "wrong", username: "alice", password: "correct-password", wantStatus: http.StatusUnauthorized},
		{name: "missing domain credentials", apiKey: "shared-token", wantStatus: http.StatusUnauthorized},
		{name: "wrong domain credentials", apiKey: "shared-token", username: "alice", password: "wrong", wantStatus: http.StatusUnauthorized},
		{name: "valid", apiKey: "shared-token", username: "alice", password: "correct-password", wantStatus: http.StatusNoContent},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/ca", nil)
			request.Header.Set("X-API-Key", test.apiKey)
			if test.username != "" || test.password != "" {
				request.SetBasicAuth(test.username, test.password)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("expected status %d, got %d", test.wantStatus, response.Code)
			}
		})
	}
}

func TestLDAPFailureReturnsServiceUnavailable(t *testing.T) {
	a := &api{
		token: "shared-token",
		authenticateLDAP: func(context.Context, string, string) error {
			return errors.New("dial failed")
		},
	}
	handler := a.authorize(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/v1/ca", nil)
	request.Header.Set("X-API-Key", "shared-token")
	request.SetBasicAuth("alice@ice.land", "correct-password")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", response.Code)
	}
}

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/ca/action", strings.NewReader(`{"action":"stop","command":"id"}`))
	response := httptest.NewRecorder()
	var destination actionRequest

	if err := decodeJSON(response, request, &destination); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", response.Code)
	}
}
