package main

import (
	"crypto/tls"
	"log/slog"

	"yat.io/yat/cmd/yat/internal/tlsdir"
)

type SharedConfig struct {
	LogLevel slog.Level
	TLSDir   string
}

func (sc SharedConfig) LoadTLSConfig(base *tls.Config) (*tlsdir.Bundle, error) {
	return tlsdir.Load(sc.TLSDir, base)
}
