package yat_test

import (
	"context"
	"log/slog"
	"net"
	"testing"

	"yat.io/yat"
)

var _ yat.Publisher = (*yat.Client)(nil)
var _ yat.Subscriber = (*yat.Client)(nil)

func TestClient(t *testing.T) {
	cc, sc := net.Pipe()
	bus := &yat.Bus{}

	go yat.ServeConn(t.Context(), sc, bus, yat.ServerConfig{
		Logger: slog.Default().With("part", "server"),
	})

	dial := func(context.Context) (net.Conn, error) {
		return cc, nil
	}

	client := yat.NewClient(dial, yat.ClientConfig{
		Logger: slog.Default().With("part", "client"),
	})

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}
