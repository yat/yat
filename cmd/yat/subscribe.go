package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"time"

	"yat.io/yat"
	"yat.io/yat/cmd/yat/internal/flagset"
)

type SubscribeCmd struct {
	clientCmd

	Limit      int
	Duration   time.Duration
	DataFormat dataFormat
}

func (cmd *SubscribeCmd) AddFlags(flags *flagset.Set) {
	flags.Int(&cmd.Limit, "limit", "n")
	flags.Duration(&cmd.Duration, "duration", "d")
	flags.Text(&cmd.DataFormat, "data-format", "F")
}

func (cmd *SubscribeCmd) Run(ctx context.Context, logger *slog.Logger, args []string) error {
	if len(args) != 1 {
		return usageError{
			Usage: "yat subscribe PATH",
			Topic: "subscribe",
		}
	}

	errC := make(chan error, 1)
	jsonOut := json.NewEncoder(os.Stdout)
	cb := func(_ context.Context, m yat.Msg) {
		printMsg := func(m yat.Msg) error {
			if cmd.DataFormat == dfRaw {
				_, err := os.Stdout.Write(m.Data)
				return err
			}

			type outMsg struct {
				Path  string `json:"path"`
				Data  any    `json:"data,omitempty"`
				Inbox string `json:"inbox,omitempty"`
			}

			data, err := dataField(m.Data, cmd.DataFormat)
			if err != nil {
				return err
			}

			om := outMsg{
				Path:  m.Path.String(),
				Data:  data,
				Inbox: m.Inbox.String(),
			}

			return jsonOut.Encode(om)
		}

		if err := printMsg(m); err != nil {
			select {
			case errC <- err:
			default:
			}
		}
	}

	path, err := yat.ParsePath(args[0])
	if err != nil {
		return err
	}

	if cmd.Limit < 0 {
		return errNegLimit
	}

	if cmd.Duration < 0 {
		return errNegDuration
	}

	sel := yat.Sel{
		Path:  path,
		Limit: cmd.Limit,
	}

	if cmd.Duration > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, cmd.Duration)
		defer cancel()
	}

	yc, err := cmd.newClient(ctx, logger)
	if err != nil {
		return err
	}

	defer yc.Close()

	sub, err := yc.Subscribe(ctx, sel, cb)
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil
		}
		return ctx.Err()

	case err := <-errC:
		return err

	case <-sub.Done():
		select {
		case err := <-errC:
			return err
		default:
			return nil
		}
	}
}

type dataFormat string

const (
	dfString = dataFormat("string")
	dfBase64 = dataFormat("base64")
	dfRaw    = dataFormat("raw")
	dfJSON   = dataFormat("json")
)

func (df dataFormat) MarshalText() (text []byte, err error) {
	return []byte(df), nil
}

func (df *dataFormat) UnmarshalText(text []byte) error {
	switch dataFormat(text) {
	case dfString, dfBase64, dfRaw, dfJSON:
		*df = dataFormat(text)
		return nil

	default:
		return errors.New("unknown format")
	}
}

func dataField(data []byte, format dataFormat) (any, error) {
	if len(data) == 0 {
		return nil, nil
	}

	switch format {
	case dfString:
		return string(data), nil

	case dfJSON:
		var value any
		if err := json.Unmarshal(data, &value); err != nil {
			return nil, err
		}
		return value, nil

	case dfBase64:
		fallthrough

	default:
		return data, nil
	}
}
