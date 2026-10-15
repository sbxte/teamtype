<!--
SPDX-FileCopyrightText: 2024 blinry <mail@blinry.org>
SPDX-FileCopyrightText: 2024 zormit <nt4u@kpvn.de>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Configuration

You can put the following options into a configuration file at `.teamtype/config`:

```ini
username = <string>
peer = <secret_address>

emit_join_code = <true/false>
emit_secret_address = <true/false>

magic_wormhole_relay = <magic_wormhole_mailbox_relay_url>
iroh_relay = <iroh_relay_url>
iroh_dns_domain = <iroh_dns_domain>
iroh_pkarr_relay = <iroh_pkarr_relay>
iroh_mdns_only = <true/false>
bind_port = <udp_port>
peer_addr = <ip:port>[,<ip:port>...]
```

After a successful `teamtype join`, the peer's secret address is automatically stored in your `.teamtype/config`.
In the future, you can then use `teamtype join` without a join code to reconnect to the same peer.

## LAN-only mode

Setting `iroh_mdns_only = true` (or passing `--mdns-only`) disables Iroh relays and the public n0 DNS/pkarr discovery.
Peers then find each other with mDNS, which only works between devices on the same local network.
No internet connection is needed, and no traffic leaves the LAN.

Because join codes are exchanged through the public Magic Wormhole service, `teamtype share --mdns-only` prints the secret address instead and skips the join code.
The other people put that secret address into their `.teamtype/config` as `peer=<secret_address>`, then run `teamtype join`.

## Dialing directly

Some networks block multicast between clients even when they are on the same LAN, so mDNS discovery fails.
If unicast works (you can `ping` the other machine), you can skip discovery and dial a known address instead.

On the host, pick a fixed port and start sharing:

    teamtype share --mdns-only --bind-port 40000

It prints the addresses it is reachable at, for example:

    peer_addr=192.168.100.233:40000,100.72.27.47:40000

The other machine puts that line in its `.teamtype/config` next to the `peer=` line, then runs `teamtype join`:

    peer=<secret_address>
    peer_addr=192.168.100.233:40000

Both `bind_port` and `peer_addr` can also be set in `.teamtype/config` instead of on the command line.
Use the host's LAN address when both machines share a LAN, or, for instance, its Tailscale address when they are connected over a tailnet.
When `share` runs without `bind_port`, the port is chosen randomly, so the printed `peer_addr` is only valid for that run.
