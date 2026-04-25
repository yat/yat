//go:build !human

package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"yat.io/yat"

	msgv1 "yat.io/yat/internal/wire/msg/v1"
)

func TestIndex(t *testing.T) {
	server := NewServer(nil, ServerConfig{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestGRPCRequestsReachAPI(t *testing.T) {
	api, err := yat.NewServer(yat.NewRouter(), yat.ServerConfig{Rules: yat.AllowAll()})
	if err != nil {
		t.Fatal(err)
	}

	server := NewServer(api, ServerConfig{})
	req := httptest.NewRequest(http.MethodPost, "https://example.test"+msgv1.MsgService_Pub_FullMethodName, nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Header.Set("content-type", "application/grpc")
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Fatalf("gRPC request was served by static fallback")
	}
	if got := rec.Header().Get("content-type"); got != "application/grpc" {
		t.Fatalf("content-type = %q, want application/grpc", got)
	}
}
