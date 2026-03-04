package yat

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

var discardLogger = ClientConfig{}.withDefaults().Logger

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

type testConn struct {
	r io.Reader

	writeErr error
	writeBuf bytes.Buffer
	closed   atomic.Bool
}

func (c *testConn) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	return c.r.Read(p)
}

func (c *testConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.writeBuf.Write(p)
}

func (c *testConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *testConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *testConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }
func (c *testConn) wrote() []byte                    { return bytes.Clone(c.writeBuf.Bytes()) }

func newTestConnWithBytes(b []byte) *testConn {
	return &testConn{r: bytes.NewReader(b)}
}

func newBareClient() *Client {
	return &Client{
		config: ClientConfig{}.withDefaults(),
		subs:   map[uint64]*clientSub{},
		wbufC:  make(chan struct{}, 1),
		doneC:  make(chan struct{}),
		connC:  make(chan struct{}),
	}
}

func newBareServerConn(conn net.Conn) *serverConn {
	return &serverConn{
		allow: AllowAll().Compile(Principal{}),
		subs:  map[uint64]*rent{},
		wbufC: make(chan struct{}, 1),
		Conn:  conn,
	}
}

func newSubFrame(num uint64, path Path) []byte {
	return appendFrame(nil, subFrameType, func(b []byte) []byte {
		b = protowire.AppendTag(b, numField, protowire.VarintType)
		b = protowire.AppendVarint(b, num)
		b = protowire.AppendTag(b, pathField, protowire.BytesType)
		b = protowire.AppendBytes(b, path.p)
		return b
	})
}

func newUnsubFrame(num uint64) []byte {
	return appendFrame(nil, unsubFrameType, func(b []byte) []byte {
		b = protowire.AppendTag(b, numField, protowire.VarintType)
		b = protowire.AppendVarint(b, num)
		return b
	})
}

func newMsgFrame(num uint64, m Msg) []byte {
	return appendFrame(nil, msgFrameType, func(b []byte) []byte {
		b = protowire.AppendTag(b, numField, protowire.VarintType)
		b = protowire.AppendVarint(b, num)
		return appendMsgFields(b, m)
	})
}

func newUnknownFrame(typ byte, body []byte) []byte {
	return appendFrame(nil, typ, func(b []byte) []byte {
		return append(b, body...)
	})
}

func appendFrames(frames ...[]byte) (out []byte) {
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}

func fillClientSignal(c *Client) {
	select {
	case c.wbufC <- struct{}{}:
	default:
	}
}

func fillServerSignal(c *serverConn) {
	select {
	case c.wbufC <- struct{}{}:
	default:
	}
}
