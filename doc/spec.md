# Yat

This is the reference manual for Yat, a system for inter-process communication.

The system is centralized: A Yat server accepts and serves connections from Yat clients. Clients connected to the same server can communicate. A client maintains a reliable full-duplex network connection to its server. If the connection is interrupted, the client retries until a new connection is established.

## Messaging

### Publishing

A Yat client can publish a message without waiting for a response.
The server will route the message and deliver it to all interested subscribers.
To be routable, a message must include a **topic path**.

A message may also include additional fields:

- A **data** payload containing opaque bytes
- An **inbox** path where responses can be published
- A **deadline** after which the message is disavowed
- A **metadata** payload containing opaque bytes

#### Topic Path

A topic path is the matter of a message. `Hello` and `a/b/c` are valid topic paths. Path elements are separated by slashes. An element can contain any byte except `/`, `*`, or NUL. See [topic/path.rl](../topic/path.rl) for a grammar.

### Subscribing

A Yat client can subscribe to a stream of messages matching a selector. When anyone connected to the same server publishes a matching message, the client receives a copy. If the client loses interest, it can end the subscription. If the client is disconnected from the server, it automatically resubscribes after reconnecting.

#### Selector

A selector describes the messages a subscriber wants to receive. It has 4 optional fields:

- **Topic** selects messages with a matching topic. It supports wildcards: `*` matches any single path element and `**` matches all trailing elements.

- **Limit** sets the maximum number of messages the subscriber will receive. If a subscription reaches its limit, it is automatically stopped.

- **Group** groups the subscriber with others who selected the same group value. When a matching message is published, it is delivered to a random member of the group.

- **Flags** is a set of selector flags. The DATA flag selects messages with at least 1 byte of data. The INBOX flag selects messages with an inbox path.

An empty selector is valid, matching nothing.

### Limits

- The maximum length of a topic path is 65535 bytes
- The maximum length of a group selector is 65535 bytes
- The maximum combined length of a message's data and metadata is 2147483647 bytes

## Wire Protocol

A client connection is a bi-directional stream of typed frames. The client writes frames to publish messages, manage subscriptions, and start RPCs; the server writes frames to deliver messages and complete RPCs. There is no handshake: After connecting, a client may immediately start writing frames. Other than a (frequent) keepalive, the server does not write unsolicited frames.

### Frames

A frame is encoded as an 8 byte header followed by a [field set](#field-sets) of varying length.

```
type FrameHeader struct {
    Len  u32le   // total frame length in bytes
    Type u16le   // describes the frame body
    _    [2]byte // reserved
}
```

| Name | Type ID | Description |
| -- | -- | -- |
| [Auth](#auth-frame) | 1 | Written by the client to identify itself |
| [Msg](#msg-frame) | 2 | Written by the client to publish a message |
| [Sub](#sub-frame) | 3 | Written by the client to start or update a subscription |
| [Unsub](#unsub-frame) | 4 | Written by the client to stop a subscription |
| [Call](#call-frame) | 5 | Written by the client to start an RPC |
| [Pkg](#pkg-frame) | 129 | Written by the server to deliver a message |
| [Ret](#ret-frame) | 130 | Written by the server to complete an RPC |

Frame type 0 is written as a keepalive.
It is discarded by the client and server.

#### Auth Frame

An Auth frame (type 1) contains a field set identifying the client.

| Field | Name | Type | Description |
| -- | -- | -- | -- |
| 1 | Token | Run | A JSON web token |

#### Msg Frame

A Msg frame (type 2) contains a message field set.

| Field | Name | Type | Description |
| -- | -- | -- | -- |
| 1 | Topic | Run | The topic path bytes |
| 2 | Inbox | Run | The inbox path bytes |
| 3 | Data | Run | Message data |
| 4 | Meta | Run | Message metadata |
| 5 | Deadline | Num | In Unix nanos |

Msg frames without a topic are discarded.

#### Sub Frame

A Sub frame (type 3) contains a field set describing a subscription.

| Field | Name | Description |
| -- | -- | -- |
| 1 | Num | A unique Num identifying the subscription |
| 2 | Topic | A Run containing a topic pattern |
| 3 | Limit | The maximum number of messages to be delivered |
| 4 | Group | A Run containing a delivery group name |
| 5 | Flags | A Num containing selector flags |

A sub frame without a topic field is discarded.

#### Unsub Frame

An Unsub frame (type 4) contains a single Num field (1) identifying the subscription.

#### Call Frame

A Call frame (type 5)

#### Pkg Frame

A Pkg frame (type 129) contains the same fields as a [Msg frame](#msg-frame), plus an additional Num field (63) identifying the subscription.

#### Ret Frame

A Ret frame (type 130)

### Field Sets

A field set is a run of bytes containing zero or more encoded fields.
The encoding is similar to the Protocol Buffers wire format, but much more limited.
Field sets are designed for structs with a small number of simple fields, mostly unsigned integers and byte slices.

A field is a 1 byte tag followed by an encoded value.
The MSB of the tag is the field type, **Num** (0) or **Run** (1).
The next bit of the tag is the field cardinality, **N** (0) or **One** (1).
The least significant 6 bits of the tag are the field number, 0-63.

#### Field Values

Num values hold a uint64 encoded as a 1-9 byte [nv](#integer-encoding).

Run values hold a run of bytes encoded as a 1-9 byte nv len followed by len bytes.

#### Field Cardinality

A field contains either a single value (cardinality 1)
or an array of values prefixed by an nv count (cardinality 0).

#### Encoding and Decoding Fields

Fields may appear in any order.
Duplicate fields may appear.

Only fields with nonzero values should be encoded. A field's value is nonzero if it contains a Num > 0 or a Run of > 0 bytes, or if the field has a cardinality of N and a count > 0.

When decoding, fields with reserved (0) or unknown field numbers should be discarded.

Two errors can occur during decoding: A short field or a Num overflow.

#### Field Set Limitations

- Structs with field counts exceeding the valid field number range (1-63) can't be encoded.

### Integer Encoding

An nv ("envy") is an encoded integer.
It is 1-65 bytes long, with a range of +- (2^512)-1.

The first byte of an nv is tagged. If the most significant bit (b7) is 0,
the entire value 0-127 is encoded in the lower 7 bits of the tagged byte.
If b7 is 1, b6 is a sign flag (1=-) and b0-b5 encode the number-1 of
following bytes, which contain the little-endian magnitude.
