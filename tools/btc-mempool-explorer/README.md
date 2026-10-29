# btc-mempool-explorer

This Compose example runs the upstream `mempool/mempool` explorer against
`bitcoin-rs` (`MEMPOOL_BACKEND=esplora`). The backend uses bitcoin-rs'
Esplora-compatible HTTP endpoints and Core-compatible JSON-RPC methods on the
same node listener. It starts no Electrum or electrs service.

`nginx-mempool.conf` keeps `/api/v1` on the Mempool backend and sends every
other `/api/` path to bitcoin-rs on `:8332/api/`, the public electrs surface
([contract WF-02](../../docs/contracts/wallet-facing.md#wf-02-operations-a-wallet-actually-issues)).
The Mempool backend uses `ESPLORA_REST_API_URL=http://node:8332/esplora`;
JSON-RPC keeps the listener root. The stack adds frontend, backend, and MariaDB
services to `bitcoin-rs`; only the frontend is public.

`txindex` and `scriptindex` are enabled so the Esplora backend can resolve
historical transactions and address activity. Index backfill and initial chain
sync must complete before those results are available.

## Run

From this directory, choose non-default RPC and database passwords, then start
the stack:

```sh
BITCOIN_RS_RPC_PASSWORD='choose-a-long-secret' \
MEMPOOL_DATABASE_PASSWORD='choose-another-long-secret' \
MEMPOOL_DATABASE_ROOT_PASSWORD='choose-a-third-long-secret' \
docker compose up --build
```

Compose requires `BITCOIN_RS_RPC_PASSWORD` whenever it loads this project, so
set it for every `docker compose` command here, including `logs` and `down`.

Open <http://127.0.0.1:8080>. The explorer HTTP port is published on all
interfaces (`0.0.0.0`). The Bitcoin RPC listener stays host-loopback only at
<http://127.0.0.1:8332> by default; P2P is published on port `8333`.

The following variables configure the stack:

| Variable | Default | Purpose |
| --- | --- | --- |
| `BITCOIN_RS_NETWORK` | `mainnet` | Shared node and Mempool network. |
| `BITCOIN_RS_LOG_LEVEL` | `info` | Node log level. |
| `BITCOIN_RS_RPC_USER` | `mempool` | Node RPC user. |
| `BITCOIN_RS_RPC_PASSWORD` | required | Node RPC password; Compose refuses to start without it. |
| `MEMPOOL_DATABASE_PASSWORD` | `change-me` | Mempool database password; set explicitly. |
| `MEMPOOL_DATABASE_ROOT_PASSWORD` | `change-me` | MariaDB root password; set explicitly. |
| `BITCOIN_RS_RPC_PORT` | `8332` | Loopback host RPC port. |
| `BITCOIN_RS_P2P_PORT` | `8333` | Host P2P port. |
| `MEMPOOL_EXPLORER_PORT` | `8080` | Host explorer HTTP port (`0.0.0.0`). |

All persistent data is stored beneath the repository-root `data/` directory:
`data/bitcoin-rs`, `data/mempool-cache`, and `data/mempool-db`. Stop the stack
with `docker compose down`; remove those directories only when the node indexes
and Mempool database can be discarded.
