// SPDX-FileCopyrightText: 2025 blinry <mail@blinry.org>
// SPDX-FileCopyrightText: 2025 zormit <nt4u@kpvn.de>
// SPDX-FileCopyrightText: 2026 axelmartensson <axel.martensson@hotmail.com>
// SPDX-FileCopyrightText: 2026 Caleb Maclennan <caleb@alerque.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data structures and helper methods around influencing the configuration of the application.

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::ops::Deref;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use docstr::docstr;
use git2::{Config as GitConfig, ConfigLevel};
use ini::{Ini, Properties};
use tempfile::{TempDir, tempdir_in};

use crate::sandbox;
use crate::setup::find_git_repo;
use crate::setup::get_app_cache_dir;
use crate::types::UserInterface;
use crate::wormhole::get_secret_address_from_wormhole;

pub(crate) const DEFAULT_SOCKET_NAME: &str = "socket";
pub(crate) const CONFIG_DIR: &str = ".teamtype";
pub(crate) const CONFIG_FILE: &str = "config";
/// Machine-written file that stores the peer learned from a join code or handshake.
/// Kept separate from [`CONFIG_FILE`], which is human-owned and never written by us.
pub(crate) const PEERS_FILE: &str = "peers";

const EMIT_SECRET_ADDRESS_DEFAULT: bool = false;
// TODO: Generate a random funny name.
const USERNAME_FALLBACK: &str = "Anonymous";

#[derive(Clone, Debug)]
pub enum Peer {
    SecretAddress(String),
    JoinCode(String),
    /// A Teamtype invite code (`tt-…`), resolved by deriving a key and dialing directly.
    InviteCode(String),
}

#[derive(Debug)]
pub enum BaseDir {
    Permanent(PathBuf),
    Temporary(TempDir),
}

impl BaseDir {
    pub fn new_temporary() -> Result<Self> {
        let parent_dir = get_app_cache_dir()?;
        let tempdir = tempdir_in(&parent_dir).context(format!(
            "Failed to create a temporary directory in the directory {}",
            parent_dir.display()
        ))?;
        Ok(Self::Temporary(tempdir))
    }
}

impl TryFrom<&Path> for BaseDir {
    type Error = anyhow::Error;

    fn try_from(path: &Path) -> Result<Self> {
        let base_dir = path.canonicalize().with_context(|| {
            format!(
                "Could not compute the absolute, canonical form of the path of directory {}",
                path.display(),
            )
        })?;
        Ok(Self::Permanent(base_dir))
    }
}

impl Deref for BaseDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Permanent(path) => path,
            Self::Temporary(temp_dir) => temp_dir.path(),
        }
    }
}

impl AsRef<Path> for BaseDir {
    fn as_ref(&self) -> &Path {
        match self {
            Self::Permanent(path) => path.as_ref(),
            Self::Temporary(dir) => dir.as_ref(),
        }
    }
}

impl Default for BaseDir {
    /// This will default to the current working directory of the process.
    fn default() -> Self {
        Self::Permanent(PathBuf::default())
    }
}

impl Display for BaseDir {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Permanent(path) => write!(f, "{}", path.display()),
            Self::Temporary(temp_dir) => write!(f, "{}", temp_dir.path().display()),
        }
    }
}

impl Clone for BaseDir {
    fn clone(&self) -> Self {
        match self {
            Self::Permanent(path) => Self::Permanent(path.clone()),
            Self::Temporary(temp_dir) => Self::Permanent(temp_dir.path().to_path_buf()),
        }
    }
}

/// Whether or not to sync version-control directories like `.git/` or `.jj/`.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub enum VcsMode {
    Sync,
    #[default]
    Ignore,
}

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub enum NetworkMode {
    #[default]
    Host,
    Peer,
}

/// How peers discover each other and how traffic is carried.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode {
    /// pkarr/DNS discovery plus Iroh relays; Magic Wormhole transports the credential.
    #[default]
    MagicWormhole,
    /// mDNS discovery, no pkarr, no relays.
    Mdns,
    /// No discovery; the peer supplies the endpoint id and address directly.
    Direct,
}

impl Mode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MagicWormhole => "magic-wormhole",
            Self::Mdns => "mdns",
            Self::Direct => "direct",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "magic-wormhole" | "magic_wormhole" | "wormhole" => Ok(Self::MagicWormhole),
            "mdns" => Ok(Self::Mdns),
            "direct" => Ok(Self::Direct),
            other => anyhow::bail!(
                "Unknown mode `{other}`. Expected one of: magic-wormhole, mdns, direct"
            ),
        }
    }
}

impl Display for Mode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.as_str())
    }
}

/// Whether the host generates a short, rotating invite code that peers can use to join.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Invite {
    Auto,
    Manual,
}

impl Invite {
    #[must_use]
    pub const fn default_for(mode: Mode) -> Self {
        match mode {
            Mode::Direct => Self::Manual,
            Mode::MagicWormhole | Mode::Mdns => Self::Auto,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "manual" => Ok(Self::Manual),
            other => anyhow::bail!("Unknown invite `{other}`. Expected one of: auto, manual"),
        }
    }
}

impl Display for Invite {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.as_str())
    }
}

/// When the host rotates its invite code.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub enum RotateCode {
    /// Never rotate; one code for the session.
    Never,
    /// Rotate after a successful code join (default).
    #[default]
    OnJoin,
    /// Rotate after any rejected credential.
    OnAttempt,
    /// Rotate on a timer.
    Periodic,
    /// Regenerate continuously.
    Continuous,
}

impl RotateCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::OnJoin => "on_join",
            Self::OnAttempt => "on_attempt",
            Self::Periodic => "periodic",
            Self::Continuous => "continuous",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "never" => Ok(Self::Never),
            "on_join" => Ok(Self::OnJoin),
            "on_attempt" => Ok(Self::OnAttempt),
            "periodic" => Ok(Self::Periodic),
            "continuous" => Ok(Self::Continuous),
            other => anyhow::bail!(
                "Unknown rotate_code `{other}`. Expected one of: never, on_join, on_attempt, periodic, continuous"
            ),
        }
    }
}

impl Display for RotateCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.as_str())
    }
}

/// Parses a duration like `10`, `10s`, `5m`, or `1h`.
pub fn parse_duration(value: &str) -> Result<std::time::Duration> {
    let value = value.trim();
    let (number, multiplier) = match value.chars().last() {
        Some('s') => (&value[..value.len() - 1], 1),
        Some('m') => (&value[..value.len() - 1], 60),
        Some('h') => (&value[..value.len() - 1], 3600),
        _ => (value, 1),
    };
    let number: u64 = number
        .trim()
        .parse()
        .with_context(|| format!("Invalid duration `{value}`"))?;
    Ok(std::time::Duration::from_secs(number * multiplier))
}

#[derive(Default, Debug, Clone)]
pub struct Config {
    pub base_dir: BaseDir,
    pub peer: Option<Peer>,
    pub emit_secret_address: bool,
    pub magic_wormhole_relay: Option<String>,
    pub iroh_relay: Option<String>,
    pub iroh_dns_domain: Option<String>,
    pub iroh_pkarr_relay: Option<String>,
    /// How peers discover each other and how traffic is carried.
    pub mode: Option<Mode>,
    /// Whether the host generates a short invite code. Defaults per mode.
    pub invite: Option<Invite>,
    /// When to rotate the invite code.
    pub rotate_code: Option<RotateCode>,
    /// How long a retired invite code stays valid.
    pub rotate_grace: Option<std::time::Duration>,
    /// Fixed UDP port for the Iroh endpoint. Useful together with `peer_addr`, so that
    /// another peer can dial this one directly without any discovery.
    pub bind_port: Option<u16>,
    /// One or more comma-separated `ip:port` addresses to dial directly, bypassing all
    /// address discovery (mDNS, DNS, relays).
    pub peer_addr: Option<String>,
    /// Endpoint id to dial in `direct` mode, e.g. when joining with an invite code and no
    /// mDNS discovery is available.
    pub peer_id: Option<String>,
    pub vcs_mode: VcsMode,
    pub username: Option<String>,
}

impl Config {
    // Merges the app config from file with the CLI app config by taking the "superset" of them.
    //
    // It depends on the attribute how we're merging it:
    // - For strings, the CLI app config attribute has precedence.
    // - For booleans, if a value deviates from the default, it "wins".
    // - The `base_dir` will be taken from the CLI app config.
    pub fn from_config_file_and_cli(config_cli: Self, ui: &UserInterface) -> Result<Self> {
        let empty_properties_section = Properties::new();
        let base_dir = config_cli.base_dir;
        let conf;
        let config_file = base_dir.join(CONFIG_DIR).join(CONFIG_FILE);
        let general_section = if config_file.exists() {
            conf = Ini::load_from_file(config_file)
                .context("Could not access config file, even though it exists")?;
            conf.general_section()
        } else {
            &empty_properties_section
        };

        // we do the computation of username before initializing the struct, because we need to
        // reference base_dir, which gets moved into the struct
        let username = get_username(config_cli.username, &base_dir, general_section, ui);

        let mode = config_cli.mode.or_else(|| {
            general_section
                .get("mode")
                .map(|m| Mode::parse(m).expect("Failed to parse config parameter `mode`"))
        });
        let invite = config_cli.invite.or_else(|| {
            general_section
                .get("invite")
                .map(|i| Invite::parse(i).expect("Failed to parse config parameter `invite`"))
        });
        let rotate_code = config_cli.rotate_code.or_else(|| {
            general_section.get("rotate_code").map(|r| {
                RotateCode::parse(r).expect("Failed to parse config parameter `rotate_code`")
            })
        });
        let rotate_grace = config_cli.rotate_grace.or_else(|| {
            general_section.get("rotate_grace").map(|r| {
                parse_duration(r).expect("Failed to parse config parameter `rotate_grace`")
            })
        });
        // We load the learned peer from the peers file, if any. This is machine-written and
        // kept separate from the human-owned config file.
        let peers_peer = read_peer_from_peers_file(&base_dir).map(Peer::SecretAddress);
        Ok(Self {
            // TODO: extract all the other fields to its own struct, s.t. we don't have to work
            // around the fact that base_dir won't ever be in the config file.
            base_dir,
            peer: config_cli
                .peer
                .or_else(|| {
                    general_section
                        .get("peer")
                        .map(|p| Peer::SecretAddress(p.to_string()))
                })
                .or(peers_peer),
            emit_secret_address: config_cli.emit_secret_address
                || general_section.get("emit_secret_address").map_or(
                    EMIT_SECRET_ADDRESS_DEFAULT,
                    |esa| {
                        esa.parse().expect(
                            "Failed to parse config parameter `emit_secret_address` as bool",
                        )
                    },
                ),
            magic_wormhole_relay: config_cli.magic_wormhole_relay.or_else(|| {
                general_section
                    .get("magic_wormhole_relay")
                    .map(ToString::to_string)
            }),
            iroh_relay: config_cli
                .iroh_relay
                .or_else(|| general_section.get("iroh_relay").map(ToString::to_string)),
            iroh_dns_domain: config_cli.iroh_dns_domain.or_else(|| {
                general_section
                    .get("iroh_dns_domain")
                    .map(ToString::to_string)
            }),
            iroh_pkarr_relay: config_cli.iroh_pkarr_relay.or_else(|| {
                general_section
                    .get("iroh_pkarr_relay")
                    .map(ToString::to_string)
            }),
            mode,
            invite,
            rotate_code,
            rotate_grace,
            bind_port: config_cli.bind_port.or_else(|| {
                general_section.get("bind_port").map(|p| {
                    p.parse()
                        .expect("Failed to parse config parameter `bind_port` as u16")
                })
            }),
            peer_addr: config_cli
                .peer_addr
                .or_else(|| general_section.get("peer_addr").map(ToString::to_string)),
            peer_id: config_cli
                .peer_id
                .or_else(|| general_section.get("peer_id").map(ToString::to_string)),
            vcs_mode: config_cli.vcs_mode,
            username: Some(username),
        })
    }

    fn peers_file(&self) -> PathBuf {
        self.base_dir.join(CONFIG_DIR).join(PEERS_FILE)
    }

    /// If we have a join code, resolve it via Magic Wormhole and store the resulting peer in
    /// the peers file. If we don't have a join code, use the configured peer. Otherwise, this
    /// is host mode and there is nothing to resolve.
    pub async fn resolve_peer(self, ui: &UserInterface) -> Result<Self> {
        let resolved_config = if let Some(peer) = self.peer.clone()
            && let Peer::JoinCode(ref join_code) = peer
        {
            let secret_address =
                get_secret_address_from_wormhole(join_code, self.magic_wormhole_relay.clone(), ui)
                    .await
                    .context(
                        "Failed to retrieve secret address, was this join code already used?",
                    )?;
            ui.log("Derived peer from join code. Storing in peers file.");
            let peers_file = self.peers_file();
            store_peer(&self.base_dir, &peers_file, &secret_address, ui)?;
            // Create a new Config struct with the resolved peer in place of the join code.
            Self {
                peer: Some(Peer::SecretAddress(secret_address)),
                ..self
            }
        } else {
            // In share mode or with already resolved peers there is no resolution needed.
            self
        };
        Ok(resolved_config)
    }

    pub(crate) const fn network_mode(&self) -> NetworkMode {
        if self.peer.is_none() {
            NetworkMode::Host
        } else {
            NetworkMode::Peer
        }
    }

    /// The resolved networking mode, defaulting to `magic-wormhole`.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode.unwrap_or_default()
    }

    /// The resolved invite setting, defaulting per mode.
    #[must_use]
    pub fn invite(&self) -> Invite {
        self.invite
            .unwrap_or_else(|| Invite::default_for(self.mode()))
    }

    /// The resolved code rotation policy.
    #[must_use]
    pub fn rotate_code(&self) -> RotateCode {
        self.rotate_code.unwrap_or_default()
    }

    /// The resolved grace period for retired invite codes.
    #[must_use]
    pub fn rotate_grace(&self) -> std::time::Duration {
        self.rotate_grace
            .unwrap_or_else(|| std::time::Duration::from_secs(10))
    }

    /// Whether the host generates an invite code in this mode. Only hosts (no configured
    /// peer) generate codes; a joining peer does not need one.
    #[must_use]
    pub fn generates_invite_code(&self) -> bool {
        self.peer.is_none()
            && matches!(self.mode(), Mode::Mdns | Mode::Direct)
            && self.invite() == Invite::Auto
    }

    /// Whether the Magic Wormhole join-code loop should run.
    #[must_use]
    pub fn emit_join_code(&self) -> bool {
        self.mode() == Mode::MagicWormhole && self.invite() == Invite::Auto
    }
}

/// Stores a peer learned at runtime (for example after a successful invite-code handshake)
/// in the peers file. Kept separate from the human-owned config file.
pub(crate) fn store_learned_peer(
    base_dir: &BaseDir,
    secret_address: &str,
    ui: &UserInterface,
) -> Result<()> {
    let peers_file = base_dir.join(CONFIG_DIR).join(PEERS_FILE);
    store_peer(base_dir, &peers_file, secret_address, ui)
}

fn store_peer(base_dir: &BaseDir, peers_file: &Path, peer: &str, ui: &UserInterface) -> Result<()> {
    ui.log(&format!(
        "Storing peer's address in {}",
        peers_file.display()
    ));

    let content = format!("peer={peer}\n");
    sandbox::write_private_file(base_dir, peers_file, content.as_bytes())
        .context("Failed to write peers file")
}

/// Reads the machine-learned peer from the peers file, if present.
fn read_peer_from_peers_file(base_dir: &BaseDir) -> Option<String> {
    let peers_file = base_dir.join(CONFIG_DIR).join(PEERS_FILE);
    if !peers_file.exists() {
        return None;
    }
    let bytes = sandbox::read_file(base_dir, &peers_file).ok()?;
    let content = String::from_utf8(bytes).ok()?;
    parse_peer_line(&content)
}

/// Parses a `peer=<secret_address>` line out of an INI-like file.
fn parse_peer_line(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        line.strip_prefix("peer=")
            .map(str::trim)
            .filter(|peer| !peer.is_empty())
            .map(ToString::to_string)
    })
}

#[must_use]
pub(crate) fn has_git_remote(base_dir: &BaseDir) -> bool {
    if let Ok(repo) = find_git_repo(base_dir)
        && let Ok(remotes) = repo.remotes()
    {
        return !remotes.is_empty();
    }
    false
}

/// Test if the local Git config has *any* user config.
pub(crate) fn has_local_user_config(base_dir: &BaseDir) -> Result<bool> {
    let snapshot = find_git_repo(base_dir)?.config()?.snapshot()?;
    let mut entries = snapshot.entries(Some("user\\."))?;
    while let Some(Ok(entry)) = entries.next() {
        match entry.level() {
            ConfigLevel::Local | ConfigLevel::Worktree | ConfigLevel::App => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}

fn get_username(
    config_cli_username: Option<String>,
    base_dir: &BaseDir,
    general_section: &Properties,
    ui: &UserInterface,
) -> String {
    config_cli_username
        .map(|u| get_username_from_cli(u, ui))
        .or_else(|| get_username_from_config_file(general_section, ui))
        .or_else(|| get_username_from_git(base_dir, ui))
        .unwrap_or_else(|| get_username_from_fallback_value(ui))
}

fn get_username_from_cli(username: String, ui: &UserInterface) -> String {
    ui.log(&format!(
        "Using the CLI provided username '{username}' to display next to the cursors other people see."
    ));
    username
}

fn get_username_from_config_file(
    general_section: &Properties,
    ui: &UserInterface,
) -> Option<String> {
    general_section
        .get("username")
        .map(ToString::to_string)
        .map(|username| {
            ui.log(&format!(
                "Using the username '{username}' from `.teamtype/config` as username, to display next to the cursors other people see."
            ));
            username
        })
}

fn get_username_from_git(base_dir: &BaseDir, ui: &UserInterface) -> Option<String> {
    let username = get_git_username(base_dir);
    if let Some(ref username) = username {
        ui.log(&docstr!(format!
                /// Using the Git username '{username}' as username, to display next to the cursors other people see.
                /// Teamtype uses the Git username as username by default.
                /// You can set the configuration value `username` in your `.teamtype/config` to override this username.
                /// You can also use the flag `--username` when using the `share`/`join` subcommands.
        ));
    }
    username
}

fn get_username_from_fallback_value(ui: &UserInterface) -> String {
    let username = USERNAME_FALLBACK.to_string();
    ui.log(&docstr!(format!
        /// Using the fallback value for username '{username}' as username, to display next to the cursors other people see.
        /// You can set the configuration value `username` in your `.teamtype/config` to override this username.
        /// You can also use the flag `--username` when using the `share`/`join` subcommands.
    ));
    username
}

#[must_use]
fn get_git_username(base_dir: &BaseDir) -> Option<String> {
    local_git_username(base_dir)
        .or_else(|_| global_git_username())
        .ok()
        .filter(|username| !username.is_empty()) // If the username is empty, return None. This can
    // happen if Git is installed, but no username is
    // set on any level of Git configuration.
}

fn local_git_username(base_dir: &BaseDir) -> Result<String> {
    Ok(find_git_repo(base_dir)?
        .config()?
        .snapshot()?
        .get_str("user.name")?
        .to_string())
}

fn global_git_username() -> Result<String> {
    Ok(GitConfig::open_default()?
        .snapshot()?
        .get_str("user.name")?
        .to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::{Context, Result};
    use tempfile::tempdir;

    use super::{BaseDir, CONFIG_DIR, PEERS_FILE, parse_peer_line, read_peer_from_peers_file};

    #[test]
    fn try_into_basedir_from_pathbuf() -> Result<()> {
        let temp = tempdir().context("Unable to create directory for tests")?;
        let dir = temp.path();
        let base_dir: BaseDir = dir.try_into()?;
        match base_dir {
            BaseDir::Permanent(ref path) => {
                assert_eq!(*path, dir.canonicalize()?);
            }
            BaseDir::Temporary(_) => panic!("Expected a permanent base directory"),
        }
        drop(base_dir);
        assert!(dir.exists(), "Permanent directory removed by drop");
        Ok(())
    }

    #[test]
    fn try_into_basedir_from_nonexistent() {
        let nonexistent = PathBuf::from("does-not-exist");
        let result: Result<BaseDir> = nonexistent.as_path().try_into();
        assert!(result.is_err());
    }

    #[test]
    fn temporary_creates_and_destroys_directory() -> Result<()> {
        let base_dir = BaseDir::new_temporary().context("Unable to create temporary directory")?;
        assert!(
            matches!(base_dir, BaseDir::Temporary(_)),
            "BaseDir not an expected temporary directory"
        );
        let path: PathBuf = base_dir.to_path_buf();
        assert!(path.exists(), "Temporary directory was not created");
        drop(base_dir);
        assert!(!path.exists(), "Temporary directory exists after drop");
        Ok(())
    }

    #[test]
    fn parses_peer_lines() {
        assert_eq!(
            parse_peer_line("peer=abc#def\n"),
            Some("abc#def".to_string())
        );
        assert_eq!(
            parse_peer_line("username=x\npeer=abc#def\n"),
            Some("abc#def".to_string())
        );
        assert_eq!(parse_peer_line(""), None);
        assert_eq!(parse_peer_line("peer=\n"), None);
        assert_eq!(parse_peer_line("peer=   \n"), None);
    }

    #[test]
    fn reads_peer_from_peers_file() -> Result<()> {
        let temp = tempdir().context("Unable to create directory for tests")?;
        let base_dir: BaseDir = temp.path().try_into()?;
        let teamtype_dir = temp.path().join(CONFIG_DIR);
        std::fs::create_dir_all(&teamtype_dir)?;

        // Missing file yields nothing.
        assert_eq!(read_peer_from_peers_file(&base_dir), None);

        std::fs::write(teamtype_dir.join(PEERS_FILE), b"peer=id#pass\n")?;
        assert_eq!(
            read_peer_from_peers_file(&base_dir),
            Some("id#pass".to_string())
        );
        Ok(())
    }
}
