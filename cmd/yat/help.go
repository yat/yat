package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
)

type helpCmd struct {
	Out io.Writer
}

//go:embed *.txt
var helpFS embed.FS

var helpSyn = map[string]string{
	"":            "help",
	"environ":     "env",
	"environment": "env",
	"publish":     "pub",
	"server":      "serve",
	"subscribe":   "sub",
	"yat":         "help",
}

func (cmd helpCmd) Run(ctx context.Context, logger *slog.Logger, cfg sharedConfig, args []string) error {
	var doc string
	if len(args) > 0 {
		doc = args[0]
	}

	if syn, ok := helpSyn[doc]; ok {
		doc = syn
	}

	help, err := fs.ReadFile(helpFS, doc+".txt")
	if err != nil {
		return errors.New("not found")
	}

	_, err = fmt.Fprintln(cmd.Out, string(help))
	return err
}
