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
```

After a successful `teamtype join`, the peer's secret address is automatically stored in your `.teamtype/config`.
In the future, you can then use `teamtype join` without a join code to reconnect to the same peer.

## LAN-only mode

Setting `iroh_mdns_only = true` (or passing `--mdns-only`) disables Iroh relays and the public n0 DNS/pkarr discovery.
Peers then find each other with mDNS, which only works between devices on the same local network.
No internet connection is needed, and no traffic leaves the LAN.

Because join codes are exchanged through the public Magic Wormhole service, `teamtype share --mdns-only` prints the secret address instead and skips the join code.
The other people put that secret address into their `.teamtype/config` as `peer=<secret_address>`, then run `teamtype join`.
