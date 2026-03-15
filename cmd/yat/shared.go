package main

import (
	"crypto/tls"
	"log/slog"
	"os"

	"yat.io/yat"
	"yat.io/yat/tlsdir"
)

type SharedConfig struct {
	LogLevel slog.Level
	TLSDir   string
}

func (sc SharedConfig) LoadTLSConfig(base *tls.Config) (*tlsdir.Bundle, error) {
	return tlsdir.Load(sc.TLSDir, base)
}

func readMsg(pstr, istr string, file string, empty bool) (m yat.Msg, err error) {
	m.Path, _, err = yat.ParsePath(pstr)
	if err != nil {
		return
	}

	if istr != "" {
		if m.Inbox, _, err = yat.ParsePath(istr); err != nil {
			return
		}
	}

	if !empty {
		if file == "-" {
			file = "/dev/stdin"
		}

		if m.Data, err = os.ReadFile(file); err != nil {
			return
		}
	}

	return
}
