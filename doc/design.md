yat message server

clients publish messages to paths
client subscribe to streams of messages
a message may contain data and an inbox path for replies

a path is a /-separated sequence of segments
empty path segments are not allowed
a path containing * or ** elements is a wildcard path
the * wildcard matches any single element (matches like a/b* are not supported)
the ** wildcard matches one or more trailing elements at the end of a path

subscribing

a client creates a subscription by selecting the set of matching messages
a subscription selects a set of messages matching a particular path
a subscription's selected path is immutable

server api

$svr/events/stop
published after the server stops accepting connections

protocol

the read loop is the same on the client and server:

- read a frame header from the connection
- if the frame type is unknown, discard the frame body and continue
- otherwise read the frame body, process the frame, and continue

frame data is often a protocol buffer: see [api/frames.proto](../api/frames.proto)

frame header

```
struct {
  Len u24le
  Type byte
}
```

frame types

- JWTFrame; optionally sent by the client to identify itself
- PubFrame; sent by the client to publish a message
- SubFrame; sent by the client to subscribe to a stream of messages
- UnsubFrame; sent by the client to cancel a subscription
- MsgFrame; sent by the server to deliver a message

transport

the native yat protocol requires TLS 1.3 over TCP
it is designed to support frame buffering on the client and efficient fanout on the server
clients and servers read and write streams of frames
