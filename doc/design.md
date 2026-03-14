yat message server
simple fanout

many clients connect to a server
clients subscribe to streams of messages
clients publish messages to a path
the server routes messages to interested clients

along with a path, a message may contain data and an inbox path for replies

a path is a /-separated sequence of segments
empty path segments are not allowed
a path containing * or ** elements is a wildcard path
the * wildcard matches any single element (matches like a/b* are not supported)
the ** wildcard matches one or more trailing elements at the end of a path

inbox paths matching @/** are reserved by the system
clients can't subscribe to a reserved inbox path
or publish a message with a reserved inbox

subscribing

a subscription selects a set of messages matching a particular path
a client subscription is identified by its number, a uint64 > 0
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
- SubFrame; sent by the client to subscribe to a stream of messages
- UnsubFrame; sent by the client to cancel a subscription
- MsgFrame; sent by the server to deliver a message

the read loop is the same on the client and server:

- read a frame header from the connection
- if the frame type is unknown, discard the frame body and continue
- otherwise read the frame body, process the frame, and continue

the frame body is often a protocol buffer: see [wire/frames.proto](../wire/frames.proto)

limits

- the maximum frame length (including header) is 16MiB
- the maximum path length is 64KiB
- the maximum group length is 1KiB
- the maximum message data length is 8MiB
- the maximum client data buffer length is 32MiB
- the maximum per-client server buffer length is 32MiB
