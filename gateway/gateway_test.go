//go:build !integration

package gateway

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Mock client
type mockClient struct{}

func (m *mockClient) Get(url string) (*http.Response, error) {
	return nil, nil
}

func (m *mockClient) Do(req *http.Request) (*http.Response, error) {
	return nil, io.EOF
}

func (m *mockClient) Transport() http.RoundTripper {
	return http.RoundTripper(nil)
}

func (m *mockClient) SetTransport(transport http.RoundTripper) {
	// No-op
}

// Unit test
func TestResetWAN_EOF(t *testing.T) {
	g := &GatewayClient{
		BaseURL:    "http://example.com",
		HTTPClient: &mockClient{},
	}

	err := g.ResetWanConnection()
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestResetWanConnection_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request")) // nolint:errcheck
	}))
	defer srv.Close()

	client := &GatewayClient{
		BaseURL:    srv.URL,
		HTTPClient: &HTTPClientWrapper{Client: srv.Client()},
	}
	err := client.ResetWanConnection()
	if err == nil {
		t.Errorf("expected error with status 400 and body, got: %v", err)
	}
}

func TestResetWanConnection_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	client := &GatewayClient{
		BaseURL:    srv.URL,
		HTTPClient: &HTTPClientWrapper{Client: srv.Client()},
	}
	err := client.ResetWanConnection()
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestGetUser_EOF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// No body, triggers EOF on decode
	}))
	defer srv.Close()

	client := &GatewayClient{
		BaseURL:    srv.URL,
		HTTPClient: &HTTPClientWrapper{Client: srv.Client()},
	}
	_, err := client.GetUser()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(errors.Unwrap(err), io.EOF) && !strings.Contains(err.Error(), "EOF") {
		t.Errorf("expected error to wrap EOF, got: %v", err)
	}
}

func TestGetUser_Non200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("fail")) // nolint:errcheck
	}))
	defer srv.Close()

	client := &GatewayClient{
		BaseURL:    srv.URL,
		HTTPClient: &HTTPClientWrapper{Client: srv.Client()},
	}
	_, err := client.GetUser()
	if err == nil || !strings.Contains(err.Error(), "status 500") || !strings.Contains(err.Error(), "fail") {
		t.Errorf("expected error with status 500 and body, got: %v", err)
	}
}

func TestGetUser_EmptyUsers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"users":[]}]`)) // nolint:errcheck
	}))
	defer srv.Close()

	client := &GatewayClient{
		BaseURL:    srv.URL,
		HTTPClient: &HTTPClientWrapper{Client: srv.Client()},
	}
	_, err := client.GetUser()
	if err == nil || !strings.Contains(err.Error(), "no user info") {
		t.Errorf("expected error about no user info, got: %v", err)
	}
}
