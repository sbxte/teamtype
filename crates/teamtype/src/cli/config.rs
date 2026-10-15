// SPDX-FileCopyrightText: 2026 Caleb Maclennan <caleb@alerque.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::env::current_dir;

use anyhow::{Context, Result};
use teamtype::config::{self, BaseDir, Config, VcsMode};
use teamtype::types::UserInterface;

use super::args::{Cli, Commands, ShareJoinFlags};

#[expect(clippy::needless_pass_by_value)]
pub fn parse_client_config(cli: Cli, _ui: &UserInterface) -> Result<Config> {
    let base_dir = resolve_directory(&cli)?;
    if matches!(cli.command, Commands::Client | Commands::SecretAddress) {
        // The only thing the client can configure at runtime is where to find the socket.
        let conf = Config {
            base_dir,
            ..Default::default()
        };
        Ok(conf)
    } else {
        unreachable!("Only Client commands beget Client configs.")
    }
}

pub fn parse_join_config(cli: Cli, ui: &UserInterface) -> Result<Config> {
    let base_dir = resolve_directory(&cli)?;
    if let Commands::Join {
        join_code,
        shared_flags:
            ShareJoinFlags {
                magic_wormhole_relay,
                iroh_relay,
                iroh_dns_domain,
                iroh_pkarr_relay,
                magic_wormhole,
                mdns,
                direct,
                invite,
                rotate_code,
                rotate_grace,
                bind_port,
                peer_addr,
                peer_id,
                secret_file,
                sync_vcs,
                username,
                ..
            },
        ..
    } = cli.command
    {
        let peer = parse_join_peer(join_code, ui)?;
        let config_cli = Config {
            base_dir,
            peer,
            emit_secret_address: false,
            magic_wormhole_relay,
            iroh_relay,
            iroh_dns_domain,
            iroh_pkarr_relay,
            mode: mode_from_flags(magic_wormhole, mdns, direct),
            invite: parse_invite(invite)?,
            rotate_code: parse_rotate_code(rotate_code)?,
            rotate_grace: parse_rotate_grace(rotate_grace)?,
            ban_max_failures: None,
            ban_window: None,
            ban_duration: None,
            bind_port,
            peer_addr,
            peer_id,
            secret_file,
            vcs_mode: from_sync_vcs_flag(sync_vcs),
            username,
        };
        let config = Config::from_config_file_and_cli(config_cli, ui)?;
        Ok(config)
    } else {
        unreachable!("Only Join commands beget Join configs.")
    }
}

pub fn parse_share_config(cli: Cli, ui: &UserInterface) -> Result<Config> {
    let base_dir = resolve_directory(&cli)?;
    if let Commands::Share {
        shared_flags:
            ShareJoinFlags {
                magic_wormhole_relay,
                iroh_relay,
                iroh_dns_domain,
                iroh_pkarr_relay,
                magic_wormhole,
                mdns,
                direct,
                invite,
                rotate_code,
                rotate_grace,
                bind_port,
                peer_addr,
                peer_id,
                secret_file,
                sync_vcs,
                username,
                ..
            },
        show_secret_address,
        ..
    } = cli.command
    {
        let config_cli = Config {
            base_dir,
            peer: None,
            emit_secret_address: show_secret_address,
            magic_wormhole_relay,
            iroh_relay,
            iroh_dns_domain,
            iroh_pkarr_relay,
            mode: mode_from_flags(magic_wormhole, mdns, direct),
            invite: parse_invite(invite)?,
            rotate_code: parse_rotate_code(rotate_code)?,
            rotate_grace: parse_rotate_grace(rotate_grace)?,
            ban_max_failures: None,
            ban_window: None,
            ban_duration: None,
            bind_port,
            peer_addr,
            peer_id,
            secret_file,
            vcs_mode: from_sync_vcs_flag(sync_vcs),
            username,
        };
        let mut config = Config::from_config_file_and_cli(config_cli, ui)?;
        // Because of the "share" subcommand, explicitly don't connect anywhere.
        config.peer = None;
        Ok(config)
    } else {
        unreachable!("Only Share commands beget Share configs.")
    }
}

// Interpret the positional join argument: a `tt-…` invite code or a Magic Wormhole code.
fn parse_join_peer(join_code: Option<String>, ui: &UserInterface) -> Result<Option<config::Peer>> {
    let Some(code) = join_code else {
        return Ok(None);
    };
    if !code.starts_with("tt-") {
        return Ok(Some(config::Peer::JoinCode(code)));
    }
    let unknown: Vec<String> = teamtype::code::code_words(&code)
        .into_iter()
        .filter(|word| !teamtype::code::is_known_word(word))
        .collect();
    if !unknown.is_empty() {
        let proceed = ui.confirm(&format!(
            "These invite-code words are not in the local word list: {}. The host may use a different word list. Continue anyway?",
            unknown.join(", ")
        ))?;
        if !proceed {
            anyhow::bail!("Aborted: invite code contains unknown words");
        }
    }
    Ok(Some(config::Peer::InviteCode(code)))
}

// Map mode flags to a `Mode`, if any was given.
fn mode_from_flags(magic_wormhole: bool, mdns: bool, direct: bool) -> Option<config::Mode> {
    if magic_wormhole {
        Some(config::Mode::MagicWormhole)
    } else if mdns {
        Some(config::Mode::Mdns)
    } else if direct {
        Some(config::Mode::Direct)
    } else {
        None
    }
}

// Parse the optional `--invite` value.
#[expect(clippy::needless_pass_by_value)]
fn parse_invite(invite: Option<String>) -> Result<Option<config::Invite>> {
    invite.as_deref().map(config::Invite::parse).transpose()
}

// Parse the optional `--rotate-code` value.
#[expect(clippy::needless_pass_by_value)]
fn parse_rotate_code(value: Option<String>) -> Result<Option<config::RotateCode>> {
    value.as_deref().map(config::RotateCode::parse).transpose()
}

// Parse the optional `--rotate-grace` value.
#[expect(clippy::needless_pass_by_value)]
fn parse_rotate_grace(value: Option<String>) -> Result<Option<std::time::Duration>> {
    value.as_deref().map(config::parse_duration).transpose()
}

// Map boolean flag inputs to config enum variants.
fn from_sync_vcs_flag(sync_vcs: bool) -> VcsMode {
    if sync_vcs {
        VcsMode::Sync
    } else {
        VcsMode::Ignore
    }
}

// Determine if the CLI flags request proceeding with a temporary directory, some user
// specified directory, or fallback to just the current directory.
fn resolve_directory(cli: &Cli) -> Result<BaseDir> {
    match cli.command {
        Commands::Share {
            shared_flags:
                ShareJoinFlags {
                    temporary_directory,
                    ..
                },
            ..
        }
        | Commands::Join {
            shared_flags:
                ShareJoinFlags {
                    temporary_directory,
                    ..
                },
            ..
        } => {
            if temporary_directory {
                return BaseDir::new_temporary();
            }
        }
        Commands::Client | Commands::SecretAddress => {}
    }
    let directory = match cli.directory {
        Some(ref directory) => directory,
        None => &current_dir().context("Could not access current directory")?,
    };
    directory.as_path().try_into()
}
