package main

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
)

type VersionCmd struct{}

func (c VersionCmd) Run(_ context.Context, _ *slog.Logger, _ SharedConfig, args []string) error {
	if len(args) > 0 {
		return usageError{
			Usage: "yat version",
		}
	}

	rev, dirty := "UNKNOWN", false
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.modified":
				dirty = s.Value == "true"

			case "vcs.revision":
				rev = s.Value
			}
		}
	}

	if dirty {
		rev = rev + "-dirty"
	}

	_, err := fmt.Printf("yat %s %s/%s\n", rev, runtime.GOOS, runtime.GOARCH)
	return err
}
