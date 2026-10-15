<!--
SPDX-FileCopyrightText: 2024 blinry <mail@blinry.org>
SPDX-FileCopyrightText: 2024 zormit <nt4u@kpvn.de>
SPDX-FileCopyrightText: 2026 Teamtype contributors

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Configuration

You can put the following options into a configuration file at `.teamtype/config`.
The file is yours: Teamtype never writes to it.
Credentials learned at runtime are stored in `.teamtype/peers` instead.

```ini
username = <string>
peer = <secret_address>
peer_id = <endpoint_id>
peer_addr = <ip:port>[,<ip:port>...]
bind_port = <udp_port>

emit_secret_address = <true/false>

magic_wormhole_relay = <magic_wormhole_mailbox_relay_url>
iroh_relay = <iroh_relay_url>
iroh_dns_domain = <iroh_dns_domain>
iroh_pkarr_relay = <iroh_pkarr_relay>

mode = magic-wormhole | mdns | direct
invite = auto | manual
rotate_code = never | on_join | on_attempt | periodic | continuous
rotate_grace = <duration, e.g. 10s>

ban_max_failures = <count>
ban_window = <duration>
ban_duration = <duration>
```

After a successful `teamtype join`, the peer's secret address is stored in `.teamtype/peers`, and you can then run `teamtype join` without a code to reconnect.

## Modes

`--magic-wormhole` (the default) uses Iroh relays plus pkarr/DNS discovery, and Magic Wormhole to hand over the secret address.
`--mdns` uses mDNS discovery on the local network, with no relays and no pkarr.
`--direct` uses no discovery at all: the peer supplies the endpoint id and address directly.

| mode | discovery | transport |
|---|---|---|
| `magic-wormhole` | pkarr/DNS | relays, then direct if possible |
| `mdns` | mDNS | direct (LAN) |
| `direct` | none | direct only |

## Invites

A host can offer a short invite code that others use to join, instead of sharing the long secret address.

    teamtype share --mdns

prints something like:

    teamtype join tt-pretty-later-woman-luxury

The other person runs that command (adding `--mdns` if needed).
The code is only valid for that host: its key is derived from the words *and* the host's endpoint id.

`invite = auto` generates a code; `invite = manual` relies on the secret address instead.
The default is `auto` for `magic-wormhole` and `mdns`, and `manual` for `direct`.

`rotate_code` controls when a code is replaced: `on_join` (default) rotates after each successful join, `on_attempt` after any rejected credential, `periodic`/`continuous` on a timer, and `never` keeps one code.
Retired codes stay valid for `rotate_grace` (default `10s`) so that peers already mid-handshake are not cut off.

The long-term secret address is always accepted. Print it with `--show-secret-address`, or at any time (without starting a daemon) with:

    teamtype secret-address

## Dialing directly

Some networks block multicast between clients even when they are on the same LAN, so mDNS discovery fails.
If unicast works (you can `ping` the other machine), you can skip discovery and dial a known address instead.

On the host, pick a fixed port and start sharing:

    teamtype share --direct --bind-port 40000

It prints its id and addresses, for example:

    --peer-id e140f9a5...3f00f01
    --peer-addr 192.168.100.233:40000,100.72.27.47:40000

The other machine supplies them and joins:

    teamtype join --direct --peer-id e140f9a5...3f00f01 --peer-addr 192.168.100.233:40000

With a code, add the code as the positional argument:

    teamtype join tt-pretty-later-woman-luxury --direct --peer-id ... --peer-addr ...

Without a code, Teamtype prompts for the passphrase once and remembers the peer in `.teamtype/peers`.

Use the host's LAN address when both machines share a LAN, or its Tailscale address when they are connected over a tailnet.
When `share` runs without `bind_port`, the port is chosen randomly, so the printed address is only valid for that run.

## Rate limiting

Invite codes are short, so the host limits guessing.
By default a source is banned for an hour after 20 rejected credentials within five minutes.
This is tunable with `ban_max_failures`, `ban_window`, and `ban_duration`.
The counter resets after a successful authentication from the same source.

Because codes can be guessed, using `invite = auto` in `--direct` mode on a globally reachable address prints a warning.
