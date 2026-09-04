# Goals

- Replace the ten flat topic-specific ZMQ endpoint/HWM fields on `Config` with a
  grouped notification configuration.
- Model ZMQ runtime configuration by its actual socket ownership boundary:
  endpoint, topics, and an optional endpoint HWM override.
- Keep the default HWM beside the ZMQ publisher and reject invalid endpoint
  groups before startup.
- Remove the legacy topic-specific CLI, environment, TOML, and `bitcoin.conf`
  configuration surface; compatibility is intentionally not preserved per
  issue #221.
- Prove grouped TOML layering, validation, runtime binding, and RPC notifier
  projection with focused tests.

