package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
)

//go:embed help/*.txt
var helpFS embed.FS

type HelpCmd struct{}

func (HelpCmd) Run(_ context.Context, _ *slog.Logger, _ SharedConfig, args []string) error {
	if len(args) > 1 {
		return usageError{
			Usage: "yat help [topic]",
		}
	}

	topic := "yat"
	if len(args) > 0 {
		topic = strings.ToLower(args[0])
	}

	// synonyms
	switch topic {
	case "pub":
		topic = "publish"

	case "sub":
		topic = "subscribe"
	}

	path := "help/" + topic + ".txt"
	help, err := fs.ReadFile(helpFS, path)

	if err != nil {
		return fmt.Errorf("yat help %s: unknown topic", topic)
	}

	_, err = fmt.Println(string(help))
	return err
}
