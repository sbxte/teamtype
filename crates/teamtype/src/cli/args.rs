// SPDX-FileCopyrightText: 2025 blinry <mail@blinry.org>
// SPDX-FileCopyrightText: 2025 zormit <nt4u@kpvn.de>
// SPDX-FileCopyrightText: 2026 axelmartensson <axel.martensson@hotmail.com>
// SPDX-FileCopyrightText: 2026 Caleb Maclennan <caleb@alerque.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::PathBuf;

use clap::builder::{BoolishValueParser, TypedValueParser as _};
use clap::{ArgAction, Args, Parser, Subcommand};

#[derive(Parser)]
#[command(about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Suppress non-essential informational messages in the console output.
    #[arg(short, long, global = true, action = ArgAction::SetTrue, value_parser = BoolishValueParser::new().map(ConsoleVerbosity::from))]
    pub quiet: ConsoleVerbosity,
    #[command(subcommand)]
    pub command: Commands,
    /// The shared directory. Defaults to current directory.
    #[arg(long, global = true)]
    pub directory: Option<PathBuf>,
}

#[derive(Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "flags are a flat set of independent CLI switches"
)]
pub struct ShareJoinFlags {
    /// EXPERIMENTAL: Also synchronize version-control directories like .git/ or .jj/, which are normally
    /// ignored. For Git, this will synchronize all branches, commits, etc. as well as your .git/config.
    /// This means that new commits will immediately appear at all peers, you can change branches together, etc.
    #[arg(long)]
    pub sync_vcs: bool,
    /// Use an alternative Magic Wormhole mailbox server relay url
    #[arg(long)]
    pub magic_wormhole_relay: Option<String>,
    /// Use an alternative Iroh relay url
    #[arg(long)]
    pub iroh_relay: Option<String>,
    /// Use an alternative Iroh DNS origin domain.
    #[arg(long)]
    pub iroh_dns_domain: Option<String>,
    /// Use an alternative Iroh Pkarr relay server.
    #[arg(long)]
    pub iroh_pkarr_relay: Option<String>,
    /// Use Magic Wormhole, pkarr/DNS discovery, and Iroh relays (default).
    #[arg(long, group = "mode")]
    pub magic_wormhole: bool,
    /// Discover peers via mDNS only. No pkarr, no relays.
    #[arg(long, group = "mode")]
    pub mdns: bool,
    /// No discovery: dial the peer's endpoint id and address directly.
    #[arg(long, group = "mode")]
    pub direct: bool,
    /// Whether the host generates a short invite code (`auto`) or relies on the long-term
    /// secret address (`manual`). Defaults: auto for magic-wormhole/mdns, manual for direct.
    #[arg(long)]
    pub invite: Option<String>,
    /// When to rotate the invite code: `never` | `on_join` | `on_attempt` | `periodic` | `continuous`.
    #[arg(long)]
    pub rotate_code: Option<String>,
    /// How long a retired invite code stays valid, e.g. `10s`.
    #[arg(long)]
    pub rotate_grace: Option<String>,
    /// Bind the Iroh endpoint to a fixed UDP port. Use this together with `--peer-addr`
    /// when mDNS discovery does not work, so the other side has a stable address to dial.
    #[arg(long)]
    pub bind_port: Option<u16>,
    /// Comma-separated `ip:port` addresses to dial directly, bypassing address discovery.
    /// Each peer can find the other's address with `ip -brief addr` (or its Tailscale IP)
    /// and the port printed by `share`.
    #[arg(long)]
    pub peer_addr: Option<String>,
    /// Endpoint id to dial directly, needed in `--direct` mode (and when joining with an
    /// invite code where mDNS discovery is unavailable).
    #[arg(long)]
    pub peer_id: Option<String>,
    /// Read the long-term passphrase (or a full `id#pass` string) from this file instead of
    /// prompting. Useful for non-interactive direct joins.
    #[arg(long)]
    pub secret_file: Option<String>,
    #[arg(long)]
    /// The name that others see next to your cursor. Defaults to your Git username.
    pub username: Option<String>,
    /// Create a new temporary directory and use it as the shared directory.
    /// The temporary directory is removed on exit.
    /// The temporary directory is created in `$XDG_CACHE_DIR/teamtype/`,
    /// or if `XDG_CACHE_DIR` is not set in `$HOME/.cache/teamtype/`,
    /// or if `HOME` is not set in `/home/$USER/.cache/teamtype/`.
    #[arg(short, long)]
    pub temporary_directory: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Share a directory with a new peer.
    Share {
        /// Re-initialize the history of the shared directory. You will loose previous history.
        #[arg(long)]
        init: bool,
        /// Print the secret address. Useful when using the invite code manually.
        #[arg(long)]
        show_secret_address: bool,
        #[command(flatten)]
        shared_flags: ShareJoinFlags,
    },
    /// Join a shared directory via a join code, or connect to the most recent one.
    Join {
        /// Specify to connect to a new peer. Otherwise, try to connect to the most recent peer.
        join_code: Option<String>,
        #[command(flatten)]
        shared_flags: ShareJoinFlags,
    },
    /// Print this directory's long-term secret address (`endpoint_id#passphrase`) and exit.
    SecretAddress,
    /// Open a JSON-RPC connection to the Teamtype daemon on stdin/stdout. Used by text editor plugins.
    Client,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleVerbosity {
    #[default]
    Verbose,
    Quiet,
}

impl From<bool> for ConsoleVerbosity {
    fn from(value: bool) -> Self {
        if value { Self::Quiet } else { Self::Verbose }
    }
}
