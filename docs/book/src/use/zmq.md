# ZeroMQ notifications

Configure a PUB endpoint in the TOML file, restart the node, and subscribe to the topics you named. The node publishes one event stream per endpoint and never buffers an unbounded backlog.

## Configure an endpoint

ZeroMQ is configured only in TOML. There are no CLI flags, no `BITCOIN_RS_*` names, and no `bitcoin.conf` aliases for it:

```toml
[notifications]
[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:55555"
topics = ["hashblock", "hashtx", "rawblock", "rawtx", "sequence"]
```

`hwm` is optional and defaults to 1,000. The endpoint must be nonempty, must have at least one topic, and may not repeat a topic. The high-water mark must be positive and fit a signed 32-bit send queue. A duplicate endpoint is refused at startup.

The node needs the `zmq` cargo feature. The default binary features include it. A build without it ignores the configured endpoints and reports no notifications.

Check what the running node registered:

```
$ curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":50,"method":"getzmqnotifications","params":[]}' -H 'content-type: application/json' http://127.0.0.1:45871/ | jq '.result'
[
  {
    "address": "tcp://127.0.0.1:55555",
    "hwm": 1000,
    "type": "pubhashblock"
  },
  {
    "address": "tcp://127.0.0.1:55555",
    "hwm": 1000,
    "type": "pubhashtx"
  },
  {
    "address": "tcp://127.0.0.1:55555",
    "hwm": 1000,
    "type": "pubrawblock"
  },
  {
    "address": "tcp://127.0.0.1:55555",
    "hwm": 1000,
    "type": "pubrawtx"
  },
  {
    "address": "tcp://127.0.0.1:55555",
    "hwm": 1000,
    "type": "pubsequence"
  }
]
```

## Wire format

Each notification is a three-part message:

1. Topic name as bytes: `hashblock`, `hashtx`, `rawblock`, `rawtx`, or `sequence`.
2. Body bytes, described below.
3. A four-byte little-endian sequence counter for that topic.

The counter is per topic and per process. It is not the mempool sequence.

| Topic | Body |
| --- | --- |
| `hashblock` | 32-byte block hash in display byte order. |
| `hashtx` | 32-byte transaction id in display byte order. |
| `rawblock` | Consensus-serialized block bytes. |
| `rawtx` | Consensus-serialized transaction bytes. |
| `sequence` | Block connect: 32-byte hash plus `C`. Block disconnect: 32-byte hash plus `D`, 33 bytes total. Mempool add or remove: 32-byte reversed txid, label `A` or `R`, then the eight-byte little-endian mempool sequence, 41 bytes total. |

A transaction mined in a connected block emits no `R` event. The block's `C` event covers it, matching Core. Every other removal reason emits `R`. The publisher sends with `DONTWAIT`. If a subscriber is slow enough to fill the endpoint queue, that notification is dropped and the node logs a debug message naming the endpoint and topic. The chain and mempool state are unaffected.

## Subscribe

This ctypes subscriber ran against a regtest node with this endpoint. It uses the system `libzmq.so.5` and reads all three frames of each message:

```python
import ctypes, sys

lib = ctypes.CDLL("libzmq.so.5")
lib.zmq_ctx_new.restype = ctypes.c_void_p
lib.zmq_socket.restype = ctypes.c_void_p
lib.zmq_socket.argtypes = [ctypes.c_void_p, ctypes.c_int]
lib.zmq_connect.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.zmq_setsockopt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
lib.zmq_msg_init.argtypes = [ctypes.c_void_p]
lib.zmq_msg_recv.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
lib.zmq_msg_size.argtypes = [ctypes.c_void_p]
lib.zmq_msg_size.restype = ctypes.c_size_t
lib.zmq_msg_data.argtypes = [ctypes.c_void_p]
lib.zmq_msg_data.restype = ctypes.c_void_p
lib.zmq_msg_close.argtypes = [ctypes.c_void_p]

ctx = lib.zmq_ctx_new()
sub = lib.zmq_socket(ctx, 2)  # ZMQ_SUB
lib.zmq_connect(sub, b"tcp://127.0.0.1:55555")
lib.zmq_setsockopt(sub, 6, ctypes.c_char_p(b""), 0)  # subscribe to everything

def frame():
    msg = ctypes.create_string_buffer(64)
    lib.zmq_msg_init(msg)
    if lib.zmq_msg_recv(msg, sub, 0) < 0:
        raise RuntimeError("no frame")
    data = ctypes.string_at(lib.zmq_msg_data(msg), lib.zmq_msg_size(msg))
    lib.zmq_msg_close(msg)
    return data

for _ in range(4):
    topic, body, seq = frame(), frame(), frame()
    print(topic.decode(), len(body), int.from_bytes(seq, "little"), body.hex()[:64])
```

Generating one block produced these four notifications:

```
topic=hashblock body_len=32 seq=1 body_prefix=767a899d48aa0445d178efcd19a981eddb171f751a1306b29cbc5cb207a7d3a5
topic=rawblock body_len=251 seq=1 body_prefix=0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73c
topic=hashtx body_len=32 seq=1 body_prefix=2b0377553a272c9e56fcd932fc8d2e7b1358187b2814348e9cea7269d6eb0690
topic=rawtx body_len=170 seq=1 body_prefix=0200000000010100000000000000000000000000000000000000000000000000
```

The block hash matches `getblockhash`; the transaction id matches the coinbase transaction. The counter value depends on how many events that topic published since process start, so subscribe before the event you care about.

## Use with a block validator

`getzmqnotifications` reports the configured `sequence` endpoint. An unmodified `bip300301_enforcer` can discover it at startup instead of requiring an external publisher or `--node-zmq-addr-sequence`. Bitcoin-rs does not change the `getnetworkinfo` version it reports, so pass `--bitcoin-core-skip-version-check` to an enforcer that rejects unknown versions.

The notification contract is [API-04](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-04-zmq-notification-contract). The sequence topic's role for the enforcer is described in [docs/rest-interface.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/rest-interface.md).

Next: [Transaction and script-hash indexes](indexes.md) make the address and history routes useful.
