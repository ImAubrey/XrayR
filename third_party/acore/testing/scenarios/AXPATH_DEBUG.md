# AXPath Debug Scenarios

This folder contains end-to-end scenario tests that generate real traffic through `acore` using `network: axpath`.

The key point is: these tests start a **real Acore server + client**, then create a **real application flow**
(HTTP download via SOCKS5) so you can debug AXPath behavior with logs.

## Baseline (No Fault Injection)

1. VLESS over TLS over AXPath file-config download

```bash
ACORE_SCENARIO_TESTS=1 \
go test ./testing/scenarios -run TestAXPathVLESSOverTLSFileConfig -v -count=1
```

Tip: to stream the spawned `acore` (client/server) logs to your terminal while the test runs, set:
- `ACORE_SCENARIO_TEE_LOGS=1`

1.1. Large file loopback (HTTP file via SOCKS + freedom)

This creates a truncated `testfile.bin` (default: 1GiB) and downloads it through:
`SOCKS inbound -> VLESS+TLS+AXPath -> freedom outbound -> local HTTP server`.

Run (Linux/macOS):
```bash
ACORE_SCENARIO_TESTS=1 \
ACORE_AXPATH_LARGE_FILE_TESTS=1 \
ACORE_SCENARIO_TEE_LOGS=1 \
ACORE_AXPATH_LOGLEVEL=debug \
ACORE_AXPATH_PAYLOAD_MIB=1024 \
go test ./testing/scenarios -run TestAXPathVLESSOverTLSFileConfig_HTTPFileLarge -v -count=1
```

Run (PowerShell):
```powershell
cd D:\Goland\Acore
$env:ACORE_SCENARIO_TESTS=1
$env:ACORE_AXPATH_LARGE_FILE_TESTS=1
$env:ACORE_SCENARIO_TEE_LOGS=1
$env:ACORE_AXPATH_LOGLEVEL="debug"
$env:ACORE_AXPATH_PAYLOAD_MIB=1024
go test ./testing/scenarios -run TestAXPathVLESSOverTLSFileConfig_HTTPFileLarge -v -count=1
```

2. Traffic loop (many sniffers + routing matchers)

```bash
ACORE_SCENARIO_TESTS=1 \
go test ./testing/scenarios -run TestAXPathTrafficLoop_AllSniffers_AllRoutingMatchers -v -count=1
```

## Fault Injection: Cut One AXPath Subflow Mid-Transfer

Test case:
- `TestAXPathVLESSOverTLSFileConfig_SubflowDownlinkCutDoesNotDisconnect`
- File: `testing/scenarios/axpath_fault_test.go`

What it does:
- Starts `server` (VLESS + TLS + AXPath) and `client` (SOCKS -> VLESS + TLS + AXPath).
- Inserts a local TCP proxy between client and server.
- The proxy will **RST/close** the downlink direction of **one** TCP connection (one AXPath subflow)
  after `cutAfterMiB` is reached (simulates NAT reset / loss / RST).
- Runs a large HTTP download through SOCKS and verifies the byte count is complete.

Run (Linux/macOS):
```bash
ACORE_SCENARIO_TESTS=1 \
ACORE_AXPATH_FAULT_TESTS=1 \
ACORE_AXPATH_LOGLEVEL=debug \
ACORE_AXPATH_PAYLOAD_MIB=256 \
ACORE_AXPATH_CUT_AFTER_MIB=4 \
ACORE_AXPATH_CUT_CONN_INDEX=0 \
go test ./testing/scenarios -run TestAXPathVLESSOverTLSFileConfig_SubflowDownlinkCutDoesNotDisconnect -v -count=1
```

Run (PowerShell):
```powershell
cd D:\Goland\Acore
$env:ACORE_SCENARIO_TESTS=1
$env:ACORE_AXPATH_FAULT_TESTS=1
$env:ACORE_AXPATH_LOGLEVEL="debug"
$env:ACORE_AXPATH_PAYLOAD_MIB=256
$env:ACORE_AXPATH_CUT_AFTER_MIB=4
$env:ACORE_AXPATH_CUT_CONN_INDEX=0
go test ./testing/scenarios -run TestAXPathVLESSOverTLSFileConfig_SubflowDownlinkCutDoesNotDisconnect -v -count=1
```

### Parameters

- `ACORE_AXPATH_PAYLOAD_MIB`
  - HTTP payload size in MiB (default: 64).
  - Use a larger value to reproduce "disconnect at byte X" issues.

- `ACORE_AXPATH_CUT_AFTER_MIB`
  - Cut (RST/close) after this many MiB have passed on the chosen subflow downlink (default: 4).

- `ACORE_AXPATH_CUT_CONN_INDEX`
  - Which accepted TCP connection is faulted (0-based, default: 0).
  - AXPath uses multiple subflows; depending on timing you may need to try `0..(subflows-1)`.

- `ACORE_AXPATH_LOGLEVEL`
  - Acore loglevel used by both client and server configs in this test (default: `debug`).

### Notes

- The test uses local loopback addresses and a self-signed TLS certificate generated at runtime.
- `maxInflightBytes` is a per-session sliding window (default: 32 MiB). Transfers can be larger than this; they
  only stall at ~`maxInflightBytes` if ACKs stop making it back to the sender.
- When debugging stalls, look for:
  - `axpath: send window full: ... last_data_ack=... last_ack_age=...`
    - This means the sender cannot enqueue more data because in-flight bytes hit `maxInflightBytes`.
    - In practice this almost always points to missing/blocked ACKs.
- When debugging disconnects, look for:
  - `axpath: subflow error: ... op=read|write ... err=... stale=... now_empty=...`
    - This prints the low-level TCP failure and whether the subflow instance was stale/replaced.
  - `axpath: session closing: ... reason=... err=... inflight_bytes=... last_ack_age=... recv_hold_bytes=...`
    - This prints the session close reason plus a state snapshot to correlate with the byte offset you see in tools like `wget`.
- If you see `axpath: reorder buffer overflow: dropping out-of-order frame` in logs, it means the out-of-order
  receive buffer hit its cap and the receiver started dropping new out-of-order frames to apply backpressure.
  Capture the printed `recv_hold_bytes/cap_bytes/dsn/recv_next_dsn` to correlate with stall/disconnect points.
