package yat

import (
	"bytes"

	"yat.io/yat/wire"
)

type Msg struct {
	Data  []byte `json:"data,omitempty"`
	Path  Path   `json:"path"`
	Reply Path   `json:"reply,omitzero"`
}

func (m Msg) Clone() Msg {
	return Msg{
		Data:  bytes.Clone(m.Data),
		Path:  m.Path.Clone(),
		Reply: m.Reply.Clone(),
	}
}

// wire returns a wire message aliasing m's fields.
func (m Msg) wire() wire.Msg {
	return wire.Msg{
		Data:  m.Data,
		Path:  m.Path.data,
		Reply: m.Reply.data,
	}
}

// parse parses a wire message into m.
func (m *Msg) parse(w wire.Msg) error {
	p := Msg{
		Data: w.Data,
	}

	var err error
	p.Path, _, err = ParsePath(w.Path)
	if err != nil {
		return err
	}

	p.Reply, _, err = ParsePath(w.Reply)
	if err != nil {
		return err
	}

	*m = p
	return nil
}
