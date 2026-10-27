# UU Relay Linux Client

An unofficial, headless Linux client for UU LAN Play rooms. It implements the authenticated room bootstrap, encrypted TCP relay, Linux TUN data path, peer discovery, direct UDP forwarding, and automatic TCP fallback without running the Windows client in a virtual machine.

> [!WARNING]
> This project is experimental and is not affiliated with, endorsed by, or supported by NetEase or UU. Use it only with your own valid account and rooms. Protocols and upstream services can change without notice.

## What is implemented

- cookie-authenticated `login/win/` → `accs` → `room/join` bootstrap;
- resume from an existing `vlan_session` cookie;
- bounded TCP connection, authentication, framing, keepalive, and reconnect-safe shutdown;
- AES-GCM, AES-ECB, plaintext, and single-byte XOR protocol handling used by the recovered room flow;
- IPv4 unicast, broadcast, and multicast forwarding through `/dev/net/tun`;
- replay filtering and source/member validation;
- `PPI!` peer announcements, WAN endpoint discovery, UDP echo confirmation, direct UDP forwarding, liveness expiry, and TCP relay fallback;
- periodic room-member refresh and best-effort offline status on shutdown;
- secret-safe configuration diagnostics and an optional gated systemd unit.

The repository contains protocol fixtures, hashes, and ABI metadata only. It does not distribute UU executables, DLLs, drivers, credentials, cookies, or room secrets.

## Requirements

- Linux with `/dev/net/tun` and `iproute2`;
- Rust 1.94 or newer for source builds;
- permission to create/configure a TUN interface (`CAP_NET_ADMIN` or root);
- a valid UU room and either a current `vlan_session` or your own login session material.

## Build and test

```bash
cargo build --release
cargo test --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

The release binary is written to `target/release/uu-linux-client`.

## Configure

Copy the example to a private location:

```bash
sudo install -d -m 0750 -o uu-lan -g uu-lan /etc/uu-linux-client
sudo install -m 0600 -o uu-lan -g uu-lan \
  examples/config.example.json \
  /etc/uu-linux-client/config.json
```

Edit the copy with your own room, assigned overlay address, and authentication material. Never commit the populated file. The client rejects group- or world-readable configuration files on Unix.

Validate local configuration without opening TUN or making network requests:

```bash
uu-linux-client check --config /etc/uu-linux-client/config.json
```

`"ok": true` confirms only local configuration validity. It does not prove room join or data-path operation.

Run interactively:

```bash
sudo target/release/uu-linux-client run \
  --config /etc/uu-linux-client/config.json \
  --interface uu0
```

Do not run two clients with the same UU room identity at the same time.

## Optional systemd service

```bash
sudo install -m 0755 target/release/uu-linux-client /usr/local/bin/uu-linux-client
sudo install -m 0644 dist/uu-linux-client.service /etc/systemd/system/uu-linux-client.service
sudo systemctl daemon-reload
```

The unit contains `ConditionPathExists=/etc/uu-linux-client/protocol-ready`. Installation intentionally leaves that gate absent and the unit disabled. After interactive validation and rollback preparation:

```bash
sudo touch /etc/uu-linux-client/protocol-ready
sudo systemctl enable --now uu-linux-client.service
```

Remove the gate or disable the unit before returning to another client using the same room identity.

## Verify local reverse-engineering evidence

The evidence manifest stores expected hashes and ABI metadata, not proprietary files:

```bash
uu-linux-client verify-evidence \
  --manifest evidence/windows-6.16.1-5251.json \
  --artifact lanplay_tun.dll \
  --path /path/to/your/extracted/lanplay_tun.dll
```

## Security notes

- Debug and JSON diagnostics redact session identifiers, tokens, mobile values, room passwords, and transport keys.
- Network and protocol parsing is fail-closed and size-bounded.
- The systemd unit uses a dedicated user, a restrictive umask, `NoNewPrivileges`, and only `CAP_NET_ADMIN`.
- Review the source and test in an isolated environment before using it on a router.

UU and related marks belong to their respective owners.
