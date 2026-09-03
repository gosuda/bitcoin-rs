# btc-mempool-explorer

This Compose example runs the upstream `mempool/mempool` explorer against
`bitcoin-rs`. The explorer backend uses bitcoin-rs' Esplora-compatible HTTP
endpoints (`MEMPOOL_BACKEND=esplora`) and its Core-compatible JSON-RPC methods
on the same node listener. It starts no Electrum or electrs service.

The stock Mempool frontend proxies `/api/v1` to the Mempool backend and every
other `/api/` path to electrs; this example mounts `nginx-mempool.conf` to send
those paths to bitcoin-rs on `:8332`, preserving the full Esplora surface.

The Mempool project has a frontend, backend, and MariaDB dependency, so this
stack contains those three services plus `bitcoin-rs`. The frontend is the only
public explorer service; the backend and database stay on the Compose network.

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

Open <http://127.0.0.1:8080>. The explorer HTTP port is published on all
interfaces (`0.0.0.0`). The Bitcoin RPC listener stays host-loopback only at
<http://127.0.0.1:8332> by default; P2P is published on port `8333`.

The following variables are optional:

| Variable | Default | Purpose |
| --- | --- | --- |
| `BITCOIN_RS_NETWORK` | `mainnet` | Shared node and Mempool network. |
| `BITCOIN_RS_RPC_USER` | `mempool` | Node RPC user. |
| `BITCOIN_RS_RPC_PASSWORD` | `change-me` | Node RPC password; set explicitly. |
| `MEMPOOL_DATABASE_PASSWORD` | `change-me` | Mempool database password; set explicitly. |
| `MEMPOOL_DATABASE_ROOT_PASSWORD` | `change-me` | MariaDB root password; set explicitly. |
| `BITCOIN_RS_RPC_PORT` | `8332` | Loopback host RPC port. |
| `BITCOIN_RS_P2P_PORT` | `8333` | Host P2P port. |
| `MEMPOOL_EXPLORER_PORT` | `8080` | Host explorer HTTP port (`0.0.0.0`). |

All persistent data is stored beneath the repository-root `data/` directory:
`data/bitcoin-rs`, `data/mempool-cache`, and `data/mempool-db`. Stop the stack
with `docker compose down`; remove those directories only when the node indexes
and Mempool database can be discarded.
