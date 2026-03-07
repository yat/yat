yat message server
simple fanout

clients publish messages to paths
client subscribe to streams of messages
a message may contain data and an inbox path for replies

a path is a /-separated sequence of segments
empty path segments are not allowed
a path containing * or ** elements is a wildcard path
the * wildcard matches any single element (matches like a/b* are not supported)
the ** wildcard matches one or more trailing elements at the end of a path

subscribing

a subscription selects a set of messages matching a particular path
subscriptions are immutable
a subscription may belong to a route group
(which is just an arbitrary name or byte seq)
when a message is routed, one subscriber in the route group is chosen to receive it
a subscription may limit the number of deliveries it receives
when a delivery limit is reached, the subscription is stopped automatically
by the client and server without the client unsubscribing

protocol

frame header

```
struct {
  Len u24le
  Type byte
}
```

frame types

- PubFrame; sent by the client to publish a message
- CallFrame; sent by the client to start a call
- SubFrame; sent by the client to subscribe to a stream of messages
- UnsubFrame; sent by the client to cancel a subscription
- MsgFrame; sent by the server to deliver a message
- RetFrame; sent by the server to finish a call

the read loop is the same on the client and server:

- read a frame header from the connection
- if the frame type is unknown, discard the frame body and continue
- otherwise read the frame body, process the frame, and continue

the frame body is often a protocol buffer: see [api/frames.proto](../api/frames.proto)
