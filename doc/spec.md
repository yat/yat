# Yat

This is the reference manual for Yat, a system for inter-process communication.

A Yat server accepts and serves connections from Yat clients. Clients connected to the same server can communicate. A client maintains a reliable full-duplex network connection to its server. If the connection is interrupted, the client retries until a new connection is established.

## Messaging

### Publishing

A Yat client can publish a message without waiting for a response.
The server will route the message and deliver it to all interested subscribers.
To be routable, a message must include a **topic path**.

Along with a topic path, a message may also include:

- An **inbox** path where responses can be published
- A **data** payload containing opaque bytes
- A **metadata** payload containing opaque bytes
- A **deadline** after which the message is late

#### Topic Path

A topic path is the matter of a message. `Hello` and `a/b/c` are valid topic paths. Path elements are separated by slashes. An element can contain any byte except `/`, `*`, or NUL. See [topic/path.rl](../topic/path.rl) for a grammar.

### Subscribing

A Yat client can subscribe to a stream of messages matching a selector. When anyone connected to the same server publishes a matching message, the client receives a copy. If the client loses interest, it can end the subscription. If the client is disconnected from the server, it automatically resubscribes after reconnecting.

#### Selecting Messages

A selector describes the messages a subscriber wants to receive. It has 3 optional fields:

- **Topic** selects messages with a matching topic. It supports wildcards: `*` matches any single path element and `**` matches all trailing elements.

- **Limit** selects the maximum number of messages the subscriber will receive. If a subscription reaches its limit, it is automatically stopped.

- **Group** groups the subscriber with others who selected the same group value. When a matching message is published, it is delivered to a random member of the group.

An empty selector is valid, matching nothing.

#### Subscription Flags

A subscription may also include a set of special flags.
The only current flag is `SubFlagResponder` (1), which tells the server that the subscription intends to publish a response to every message it receives. When this flag is set, the server will only deliver messages to the subscription if they have an inbox.

### Limits

- The maximum length of a topic path is 65535 bytes
- The maximum length of a group selector is 65535 bytes
- The maximum combined length of a message's data and metadata is 2147483647 bytes

## Wire Protocol

A client connection is wrapped by a bi-directional stream of typed frames. The client writes frames to publish messages and manage subscriptions; the server writes frames to deliver messages. There is no handshake: After connecting, a client may immediately start writing and reading frames. Other than a (frequent) keepalive, the server does not write unsolicited frames.

### Wire Frames

A frame is encoded as an 8 byte header followed by a body of varying length.
Most frame bodies contain a [field set](#field-sets).

```
type FrameHeader struct {
    Len  u32le   // total frame length in bytes
    Type u16le   // describes the frame body
    _    [2]byte // reserved
}
```

| Name | Type ID | Description |
| -- | -- | -- |
| [Msg](#msg-frame) | 2 | Written by the client to publish a message |
| [Sub](#sub-frame) | 3 | Written by the client to start or update a subscription |
| [Unsub](#unsub-frame) | 4 | Written by the client to stop a subscription |
| [Pkg](#pkg-frame) | 128 | Written by the server to deliver a message |

Frame type 0 is written by the client and server as a keepalive.
Frame type 1 is reserved.

#### Msg Frame

A Msg frame contains a message field set.

| Field | Name | Type | Description |
| -- | -- | -- | -- |
| 1 | Topic | Run | The topic path bytes |
| 2 | Inbox | Run | The inbox path bytes |
| 3 | Data | Run | Message data |
| 4 | Meta | Run | Message metadata |
| 5 | Deadline | Num | In Unix nanos |

A Msg frame without a topic is discarded by the server.
A Msg frame with a deadline in the past is discarded by the server.

#### Sub Frame

A Sub frame contains a field set describing a subscription.

| Field | Name | Type | Description |
| -- | -- | -- | -- |
| 1 | Number | Num | Subscription number |
| 2 | Topic | Run | Topic pattern |
| 3 | Limit | Num | Max deliveries |
| 4 | Group | Run | Delivery group name |
| 5 | Flags | Num | Subscription flags |

If a Sub frame is missing a topic field, it is discarded by the server.

#### Unsub Frame

An Unsub frame contains a single field (1) identifying the subscription.

#### Pkg Frame

A Pkg frame (type 128) contains the same field set as a [Msg frame](#msg-frame), plus an additional field 127 containing the subscription number.
If a Pkg frame is missing a topic field, it is discarded by the client.
If a Pkg frame has a deadline in the past, it is discarded by the client.

### Field Sets

A field set is a run of bytes containing zero or more encoded fields.
The encoding is similar to the Protocol Buffers wire format, but much more limited.
Field sets are designed for structs with a small number of fields containing unsigned integers and byte slices.
Repeated fields and nested structs are not supported.

A field is a 1 byte tag followed by an encoded value.
The MSB of the tag is the field type, **Value** (0) or **Run** (1).
The least significant 7 bits of the tag are the field number, 0-127.

#### Field Types

Values hold a uint64 encoded as a 1-9 byte [nv](#integer-encoding).

Runs hold a run of bytes encoded as an nv len followed by len bytes.

#### Encoding and Decoding Fields

Fields may appear in any order.
Duplicate fields may appear.

Fields with zero values and runs of 0 bytes should not be encoded.

When decoding, unknown fields should be discarded.
When decoding multiple fields with the same number, the latest field wins.

Two errors can occur during decoding: A short field or a Num overflow.

#### Field Set Limitations

- Field 0 is reserved
- Structs with field counts exceeding the valid field number range (1-127) can't be encoded

### Integer Encoding

An nv ("envy") is an encoded integer.
It is 1-65 bytes long, with a range of +- (2^512)-1.

The first byte of an nv is tagged.
If the most significant bit (b7) is 0, the entire value 0-127 is encoded in the lower 7 bits of the tagged byte.
If b7 is 1, b6 is a sign flag (1=-) and b5-b0 encode the number-1 of following bytes, which contain the little-endian magnitude.
