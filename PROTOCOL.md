# The traffic-inspector tunnel protocol

Version 1.  The transport is UDP, the payload is always encrypted with
AES-256-GCM.

## Frame layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    version    |     type      |     flags     |    reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            length             |            flow id            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            nonce                              |
|                           (12 bytes)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  ciphertext (length bytes)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          tag (16 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* `version` is `1`.
* `type` is one of the frame types below.
* `flags` bit 0 (`0x01`) marks a DATA frame that carries a UDP datagram.
* `length` is the size of the plaintext payload, at most 1200 bytes.
* `flow id` identifies the flow a frame belongs to.  The client picks it and
  it is unique for the lifetime of a session.
* `nonce` is `session id (8 bytes) || counter (4 bytes, big endian)`.
* `tag` is the GCM authentication tag.

The 10 byte header is **not encrypted** but it **is authenticated**: it is
passed to GCM as Additional Authenticated Data, so an attacker cannot rewrite
a frame type or a flow id in flight without invalidating the tag.

The whole datagram (header + nonce + ciphertext + tag) is at most
`10 + 12 + 1200 + 16 = 1238` bytes, which fits comfortably in a 1500 byte path
MTU.

## Frame types

| Value | Name | Direction | Payload |
|---|---|---|---|
| `0x00` | `HELLO` | client -> server | `client id (8) || client nonce (8) || proof (16) || device label` |
| `0x01` | `HELLO_ACK` | server -> client | `server id (8) || server nonce (8) || proof (16)` |
| `0x02` | `OPEN` | client -> server | see below |
| `0x03` | `OPEN_OK` | server -> client | `status (1)` |
| `0x04` | `DATA` | both | payload bytes |
| `0x05` | `CLOSE` | both | `reason (1)` |
| `0x06` | `PING` | both | empty |
| `0x07` | `PONG` | both | empty |

### The device label

The `HELLO` frame ends with the name the client gives itself: one length
byte and up to 255 bytes of UTF-8, for example `pixel8-android` or
`laptop-linux`.  The server shows it in the inspector, which is what makes
it possible to follow one device over time - the `client id` is random and
changes with every connection.

The label is only a name.  The server cannot verify it, but it cannot be
changed in flight either, because it travels inside the sealed frame.

### OPEN payload

```
protocol (1)          6 = TCP, 17 = UDP
source address        address family (1) + address
source port (2)
destination address   address family (1) + address
destination port (2)
```

Address families: `0x00` any, `0x01` IPv4 (4 bytes), `0x03` domain
(1 length byte + the name), `0x04` IPv6 (16 bytes).

The source address is what the device's own stack used; the server records it
in the inspector but never uses it to route anything.  The destination may be
a domain name, in which case the **server** resolves it - that keeps DNS
inside the tunnel and gives the inspector a readable destination.

### DATA payload

* TCP: raw bytes of the stream.  The receiver reassembles them in order.
* UDP: `total length (2) || chunk`.  A datagram larger than one frame is
  split into several DATA frames and reassembled by the receiver.

### OPEN_OK status

`0` ok, `1` bad request, `2` name not resolved, `3` refused, `4` timeout,
`5` connect failed, `6` protocol not supported, `7` flow already exists,
`8` too many flows.

### CLOSE reason

`0` normal, `1` error, `2` timeout, `3` reset by peer, `4` server shutdown.

## The handshake

The master key is a shared secret between the client and the server.  It
never travels over the wire.

1. The client generates a random `client id` and `client nonce` and sends a
   `HELLO` frame sealed with the master key and a random nonce.  The payload
   carries `HMAC-SHA256(master, "ti-hello-v1" || client id || client nonce)`
   truncated to 16 bytes.
2. The server verifies the proof, generates its own `server id` and
   `server nonce`, and answers with a `HELLO_ACK` sealed the same way.  The
   proof is
   `HMAC-SHA256(master, "ti-ack-v1" || client id || server id || client
   nonce || server nonce)`.
3. Both sides derive the session key:
   `HKDF-SHA256(ikm = master, salt = client id || server id || client nonce
   || server nonce, info = "traffic-inspector/1", length = 32)`.

Everything after the handshake uses the session key.  A client that does not
know the master key cannot produce a valid proof, and a replayed handshake is
useless because it derives a brand new session key.

## Nonces

The nonce of a frame is `session id (8 bytes) || counter (4 bytes)`.  The two
directions use different session ids, so the nonce is unique for the whole
session without any random draw per frame.  The receiver checks the counter
and rejects anything that is not exactly the expected value, which also
catches replayed and reordered frames.

## Flow life cycle

```
client                                        server
  |                                             |
  |--- HELLO ------------------------------------>|
  |<-- HELLO_ACK --------------------------------|
  |                                             |
  |--- OPEN (flow 1, 10.8.0.2:52344 -> host:443) ->|
  |                                             |  connect to the destination
  |<-- OPEN_OK (0) ------------------------------|  (TCP: once the handshake is done)
  |                                             |
  |--- DATA (flow 1) -------------------------->|  -> destination
  |<-- DATA (flow 1) ---------------------------|  <- destination
  |                                             |
  |--- CLOSE (flow 1) ------------------------->|
  |<-- CLOSE (flow 1) --------------------------|
```

Several flows may be open at the same time, in both directions, and each one
has its own socket on the server.
