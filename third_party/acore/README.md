# Acore

Acore is a high-performance network proxy core derived from the MPL-2.0 licensed XTLS/Xray-core project, with local rebranding and updates noted below. This fork is not an official XTLS project.

## Status of this repo

- Routing destination unification: routing rules use a single `destination` field that can target an outbound or a balancer, and it may be a string or `{ tag, vlessRoute }`.
- Routing `vlessRoute` also supports quick-target arrays such as `["53:direct", "443,1000-2000:proxy"]`; matched entries detour directly, unmatched traffic can continue through `ruleTag` chaining.
- Outbound/balancer namespaces merged with conflict checks (duplicate names are rejected at startup).
- Nested balancers supported with cycle detection (startup fails on loops).
- Dialer proxy can resolve balancers via router destinations.
- Metrics gRPC adds missing connection metadata (local and Acore source addresses).
- UI state persistence in `acore.ui.json` (or `acore.ui.yaml` / `acore.ui.yml` when using YAML configs) under `controller.uiState`, with a dedicated `/ui/state` endpoint.

## Features

### Protocols (inbound/outbound)

- vless, vmess, trojan, shadowsocks, shadowsocks2022
- socks, http, dokodemo-door
- wireguard, dns
- freedom, blackhole, loopback

### Transports

- tcp, tls, websocket, grpc
- httpupgrade, splithttp
- kcp, udp
- reality

### Routing and balancing

- Rule-based routing with destination targets (outbound or balancer), including optional VLESS route marking on destination objects.
- Rule-based routing also supports VLESS route quick-target arrays for direct outbound selection by UUID bytes 7-8.
- Balancer strategies with runtime override support.
- Outbound/balancer name conflict detection.

### Observability and control

- Connection tracking and traffic stats.
- Observatory and burst observatory for health checks.
- Metrics HTTP endpoints (connections, nodes, rules, logs, config patch, UI state).
- Metrics gRPC service for the same core signals.

### UI

- `ui/` (React) frontend and `controller-ui/` proxy backend.
- Settings file: `acore.ui.json` (or `acore.ui.yaml` / `acore.ui.yml` when using YAML configs), created/updated by metrics `/settings`.
- UI state: stored inside the same file under `controller.uiState` (updated by metrics `/ui/state`).

## API updates (local)

- Metrics HTTP: add `/ui/state` for UI state read/write.
- Metrics gRPC: connection metadata now includes local and Acore source addresses.
- Routing config patch accepts destination-based targets (outbound or balancer).
- Config readers accept merged routing schema (legacy fields mapped into `destination`).

## JSON files (local)

- `acore.ui.json`: settings + UI state (`controller.uiState`) for metrics/UI integration.
- When the main config file (the one that defines `log`) is YAML, metrics persists the same payload as `acore.ui.yaml` (or `acore.ui.yml` for `.yml`).
- Legacy: separate UI state files can still be used via `UI_STATE_FILE`, but are no longer created by default.

## Build

```bash
go build -o acore ./main
```

### Cross-compile (Linux amd64)

```bash
GOOS=linux GOARCH=amd64 go build -o acore-linux-amd64 ./main
```

## Run

```bash
acore run -c config.json
acore run -c config.yaml
```

Multiple config files and a config directory are supported:

```bash
acore run -c config.json -c extra.json
acore run -c config.yaml -c extra.yaml
acore run -confdir /path/to/configs
```

## Configuration notes

- Main config supports JSON/JSONC/YAML/TOML (`-format auto` detects format by file extension).
- YAML/TOML are converted to JSON before parsing, so field names match the JSON schema.
- Burst observatory TCP mode is enabled by setting `burstObservatory.pingConfig.tcping = true`.
- Local config parsing notes (including YAML) and schema merges: `docs/CONFIG_JSON.md`.

## License

Mozilla Public License 2.0. See `LICENSE`.

This repository preserves the original MPL-2.0 license terms for files derived from XTLS/Xray-core. Acore-specific changes are distributed under the same license unless a file states otherwise.

Third-party dependency license notes are tracked in `THIRD_PARTY_LICENSES.md`.

## Links

- Project X: https://github.com/XTLS
- Original upstream: https://github.com/XTLS/Xray-core
- Acore repository: https://github.com/ImAubrey/acore
- Documentation: https://xtls.github.io
