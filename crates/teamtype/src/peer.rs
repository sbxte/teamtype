// SPDX-FileCopyrightText: 2024 blinry <mail@blinry.org>
// SPDX-FileCopyrightText: 2024 zormit <nt4u@kpvn.de>
// SPDX-FileCopyrightText: 2026 Caleb Maclennan <caleb@alerque.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! This module provides a [`ConnectionManager`], which can be used to connect to other daemons.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::StreamExt as _;
use iroh::address_lookup::DnsAddressLookup;
use iroh::address_lookup::pkarr::PkarrPublisher;
use iroh::endpoint::{
    Connection as IrohEndpointConnection, IncomingAddr, RecvStream, RelayMode, SendStream, presets,
};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMap, RelayUrl, SecretKey};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use postcard::{from_bytes, to_allocvec};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::sleep;
use tracing::debug;
use url::Url;

use self::sync::{Connection, PeerMessage, SyncActor};
use crate::code;
use crate::config::{BaseDir, CODE_FILE, Config, Mode, RotateCode};
use crate::daemon::DocumentActorHandle;
use crate::types::UserInterface;

mod sync;

const ALPN: &[u8] = b"/teamtype/1";
/// mDNS service name for advertisement and discovery. Versioned so the protocol can evolve.
const MDNS_SERVICE_NAME: &str = "teamtype1";
/// How long a joiner collects mDNS candidates before giving up on discovery.
const DISCOVERY_WINDOW: Duration = Duration::from_secs(3);
/// Per-attempt timeout when trying a code against discovered hosts.
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

struct SecretAddress {
    endpoint_addr: EndpointAddr,
    passphrase: SecretKey,
}

impl FromStr for SecretAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('#').collect();
        if parts.len() != 2 {
            bail!("Peer string must have format <endpoint_id>#<passphrase>");
        }

        let endpoint_addr = PublicKey::from_str(parts[0])?.into();
        let passphrase = SecretKey::from_str(parts[1])?;

        Ok(Self {
            endpoint_addr,
            passphrase,
        })
    }
}

/// Tracks the host's accepted credentials: the long-term passphrase `P` plus the current
/// invite code and a grace window of recently retired codes.
struct CodeState {
    endpoint_id: [u8; 32],
    long_term: SecretKey,
    current: Option<(String, SecretKey)>,
    retired: Vec<(SecretKey, Instant)>,
    grace: Duration,
    rotate: RotateCode,
    base_dir: BaseDir,
    /// When true, persist the code so it survives restarts (`rotate_code = never`).
    persist: bool,
    ui: UserInterface,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Credential {
    LongTerm,
    Code,
}

impl CodeState {
    fn new(
        endpoint_id: [u8; 32],
        long_term: SecretKey,
        grace: Duration,
        rotate: RotateCode,
        base_dir: BaseDir,
        ui: &UserInterface,
    ) -> Self {
        let persist = rotate == RotateCode::Never;
        Self {
            endpoint_id,
            long_term,
            current: None,
            retired: Vec::new(),
            grace,
            rotate,
            base_dir,
            persist,
            ui: ui.clone(),
        }
    }

    fn code_file_path(&self) -> std::path::PathBuf {
        self.base_dir
            .join(crate::config::CONFIG_DIR)
            .join(CODE_FILE)
    }

    /// Uses a persisted code when `rotate_code = never`, otherwise generates one.
    fn load_or_rotate(&mut self) {
        if self.persist
            && let Ok(bytes) = fs::read(self.code_file_path())
        {
            let code = String::from_utf8_lossy(&bytes).trim().to_string();
            if !code.is_empty() {
                let key = SecretKey::from_bytes(
                    &code::derive_key(&code, &self.endpoint_id)
                        .expect("Failed to derive invite key"),
                );
                self.ui.inform(&format!("Reusing invite code: {code}"));
                self.current = Some((code, key));
                return;
            }
        }
        self.rotate();
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.retired.retain(|(_, expires)| *expires > now);
    }

    /// Retires the current code (if any) and generates a fresh one, printing it.
    fn rotate(&mut self) {
        self.prune();
        if let Some((_, key)) = self.current.take() {
            self.retired.push((key, Instant::now() + self.grace));
        }
        let code = code::generate();
        let key = SecretKey::from_bytes(
            &code::derive_key(&code, &self.endpoint_id).expect("Failed to derive invite key"),
        );
        self.ui.inform(&format!(
            "One other person can use this to connect to you:\n\n   teamtype join {code}\n"
        ));
        if self.persist {
            let path = self.code_file_path();
            if let Err(err) =
                crate::sandbox::write_private_file(&self.base_dir, &path, code.as_bytes())
            {
                self.ui
                    .warn(&format!("Failed to persist invite code: {err}"));
            }
        }
        self.current = Some((code, key));
    }

    fn long_term(&self) -> &SecretKey {
        &self.long_term
    }

    fn check(&mut self, presented: &[u8; 32]) -> Option<Credential> {
        self.prune();
        if constant_time_eq::constant_time_eq(presented, &self.long_term.to_bytes()) {
            return Some(Credential::LongTerm);
        }
        if let Some((_, key)) = &self.current
            && constant_time_eq::constant_time_eq(presented, &key.to_bytes())
        {
            return Some(Credential::Code);
        }
        for (key, _) in &self.retired {
            if constant_time_eq::constant_time_eq(presented, &key.to_bytes()) {
                return Some(Credential::Code);
            }
        }
        None
    }

    fn on_success(&mut self, used_code: bool) {
        if used_code && self.rotate == RotateCode::OnJoin {
            self.rotate();
        }
    }

    fn on_failure(&mut self) {
        if self.rotate == RotateCode::OnAttempt {
            self.rotate();
        }
    }
}

#[expect(
    clippy::large_enum_variant,
    reason = "the joiner credential is a fixed 32-byte key, boxing it saves little"
)]
enum PeerAuth {
    /// Host side: accepts `P` and any live invite-code key.
    Host(Arc<Mutex<CodeState>>),
    /// Joiner side: presents a credential, and expects the host to reply with `P` when the
    /// credential was a code.
    Joiner {
        credential: SecretKey,
        expect_reply: bool,
    },
}

/// Per-source-IP failure counter with a rolling window and a temporary ban.
struct RateLimiter {
    max_failures: u32,
    window: Duration,
    ban: Duration,
    entries: HashMap<IpAddr, FailureEntry>,
}

struct FailureEntry {
    count: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
}

impl RateLimiter {
    fn new(max_failures: u32, window: Duration, ban: Duration) -> Self {
        Self {
            max_failures,
            window,
            ban,
            entries: HashMap::new(),
        }
    }

    fn is_banned(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if let Some(entry) = self.entries.get_mut(&ip)
            && let Some(until) = entry.banned_until
        {
            if until > now {
                return true;
            }
            entry.banned_until = None;
            entry.count = 0;
            entry.window_start = now;
        }
        false
    }

    fn record_failure(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let max = self.max_failures;
        let ban = self.ban;
        let window = self.window;
        let entry = self.entries.entry(ip).or_insert_with(|| FailureEntry {
            count: 0,
            window_start: now,
            banned_until: None,
        });
        if now.duration_since(entry.window_start) > window {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;
        if entry.count >= max {
            entry.banned_until = Some(now + ban);
        }
    }

    fn record_success(&mut self, ip: IpAddr) {
        self.entries.remove(&ip);
    }
}

pub struct ConnectionManager {
    message_tx: mpsc::Sender<EndpointMessage>,
    secret_address: String,
    direct_addresses: Vec<SocketAddr>,
    peer_addr: Vec<SocketAddr>,
    mdns: Option<MdnsAddressLookup>,
}

impl ConnectionManager {
    pub async fn new(
        config: &Config,
        document_handle: DocumentActorHandle,
        ui: &UserInterface,
    ) -> Result<Self> {
        let (message_tx, message_rx) = mpsc::channel(1);

        let (endpoint, my_passphrase, mdns) = Self::build_endpoint(config).await?;

        let encoded_passphrase = data_encoding::HEXLOWER.encode(&my_passphrase.to_bytes());
        let secret_address = format!("{}#{}", endpoint.id(), encoded_passphrase);
        let direct_addresses = Self::local_direct_addresses(&endpoint);
        let peer_addr = Self::parse_peer_addr(config.peer_addr.as_deref())?;

        let code_state = Arc::new(Mutex::new(CodeState::new(
            *endpoint.id().as_bytes(),
            my_passphrase.clone(),
            config.rotate_grace(),
            config.rotate_code(),
            config.base_dir.clone(),
            ui,
        )));
        if config.generates_invite_code() {
            code_state.lock().await.load_or_rotate();
            Self::spawn_rotation(config, &code_state);
        }

        let mut actor = EndpointActor::new(
            endpoint,
            message_rx,
            message_tx.clone(),
            document_handle,
            code_state.clone(),
            Arc::new(Mutex::new(RateLimiter::new(
                config.ban_max_failures(),
                config.ban_window(),
                config.ban_duration(),
            ))),
            config.base_dir.clone(),
            ui,
        );

        tokio::spawn(async move { actor.run().await });

        Ok(Self {
            message_tx,
            secret_address,
            direct_addresses,
            peer_addr,
            mdns,
        })
    }

    /// Spawns the timer for `periodic`/`continuous` code rotation, if configured.
    fn spawn_rotation(config: &Config, code_state: &Arc<Mutex<CodeState>>) {
        let interval = match config.rotate_code() {
            RotateCode::Continuous => Duration::from_millis(500),
            RotateCode::Periodic => config.rotate_grace().max(Duration::from_secs(60)),
            _ => return,
        };
        let code_state = code_state.clone();
        tokio::spawn(async move {
            loop {
                sleep(interval).await;
                code_state.lock().await.rotate();
            }
        });
    }

    pub fn secret_address(&self) -> &str {
        &self.secret_address
    }

    /// The `ip:port` addresses this endpoint is reachable at, for use with
    /// `peer_addr` / `--peer-addr` on a peer when discovery does not work.
    #[must_use]
    pub fn direct_addresses(&self) -> &[SocketAddr] {
        &self.direct_addresses
    }

    pub async fn connect(&self, secret_address: String) -> Result<()> {
        let mut secret_address = SecretAddress::from_str(&secret_address)?;
        for addr in &self.peer_addr {
            secret_address.endpoint_addr = secret_address.endpoint_addr.with_ip_addr(*addr);
        }
        self.send_connect(secret_address, false).await
    }

    async fn send_connect(&self, secret_address: SecretAddress, expect_reply: bool) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.message_tx
            .send(EndpointMessage::Connect {
                secret_address,
                response_tx: Some(response_tx),
                expect_reply,
                allow_reconnect: !expect_reply,
                previous_attempts: 0,
            })
            .await
            .expect("EndpointActor task has been killed");
        response_rx.await??;
        Ok(())
    }

    /// Connects using an invite code. In `mdns` mode the host id is discovered; otherwise the
    /// id must be supplied (e.g. via `peer_id` in `--direct` mode).
    pub async fn connect_with_code(
        &self,
        invite_code: &str,
        peer_id: Option<PublicKey>,
    ) -> Result<()> {
        let candidates = match peer_id {
            Some(id) => vec![id],
            None => self.discover_candidates().await?,
        };
        if candidates.is_empty() {
            bail!("No Teamtype hosts found on the local network");
        }

        let mut last_err = None;
        for id in candidates {
            let key = code::derive_key(invite_code, id.as_bytes())?;
            let mut endpoint_addr: EndpointAddr = id.into();
            for addr in &self.peer_addr {
                endpoint_addr = endpoint_addr.with_ip_addr(*addr);
            }
            let secret_address = SecretAddress {
                endpoint_addr,
                passphrase: SecretKey::from_bytes(&key),
            };
            let attempt = tokio::time::timeout(
                CONNECT_ATTEMPT_TIMEOUT,
                self.send_connect(secret_address, true),
            )
            .await;
            match attempt {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(err)) => last_err = Some(err),
                Err(_) => last_err = Some(anyhow::anyhow!("connection attempt timed out")),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Invite code did not match any host")))
    }

    /// Collects endpoint ids advertised over mDNS for a short window.
    async fn discover_candidates(&self) -> Result<Vec<PublicKey>> {
        let Some(mdns) = &self.mdns else {
            return Ok(Vec::new());
        };
        let mut ids = Vec::new();
        let mut stream = mdns.subscribe().await;
        let deadline = tokio::time::Instant::now() + DISCOVERY_WINDOW;
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(DiscoveryEvent::Discovered { endpoint_info, .. })) => {
                    let id = endpoint_info.endpoint_id;
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                }
                Ok(Some(DiscoveryEvent::Expired { .. })) => {}
                Ok(Some(_) | None) | Err(_) => break,
            }
        }
        Ok(ids)
    }

    /// Parses a comma-separated list of `ip:port` addresses.
    fn parse_peer_addr(peer_addr: Option<&str>) -> Result<Vec<SocketAddr>> {
        let Some(peer_addr) = peer_addr else {
            return Ok(Vec::new());
        };
        peer_addr
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                SocketAddr::from_str(s).with_context(|| format!("Invalid peer_addr entry: {s}"))
            })
            .collect()
    }

    /// Enumerates the `ip:port` addresses this endpoint listens on, so the user can
    /// copy one into the other peer's `peer_addr` config.
    fn local_direct_addresses(endpoint: &Endpoint) -> Vec<SocketAddr> {
        let ports: Vec<u16> = endpoint
            .bound_sockets()
            .iter()
            .map(SocketAddr::port)
            .collect();
        let mut addrs = Vec::new();
        if let Ok(interfaces) = if_addrs::get_if_addrs() {
            for interface in interfaces {
                if interface.is_loopback() || !interface.is_oper_up() {
                    continue;
                }
                for port in &ports {
                    let addr = SocketAddr::new(interface.ip(), *port);
                    if !addrs.contains(&addr) {
                        addrs.push(addr);
                    }
                }
            }
        }
        addrs
    }

    async fn build_endpoint(
        config: &Config,
    ) -> Result<(Endpoint, SecretKey, Option<MdnsAddressLookup>)> {
        let (secret_key, my_passphrase) = Self::get_keypair(&config.base_dir);

        let builder = match config.mode() {
            // LAN-only: no relays, no n0 DNS/pkarr. Discovery is mDNS only. The mDNS lookup is
            // added after binding so we can keep a handle for candidate discovery.
            // LAN-only and direct both have no relays and no n0 DNS/pkarr. In mDNS mode the
            // lookup is added after binding so we can keep a handle for candidate discovery;
            // direct mode dials only supplied addresses.
            Mode::Mdns | Mode::Direct => Endpoint::builder(presets::Minimal)
                .secret_key(secret_key)
                .alpns(vec![ALPN.to_vec()])
                .relay_mode(RelayMode::Disabled),
            Mode::MagicWormhole => {
                let mut builder = Endpoint::builder(presets::N0)
                    .secret_key(secret_key)
                    .alpns(vec![ALPN.to_vec()]);

                let relay_mode = match &config.iroh_relay {
                    Some(iroh_relay) => {
                        let relay_url = RelayUrl::from_str(iroh_relay)?;
                        let relay_map = RelayMap::from(relay_url);
                        RelayMode::Custom(relay_map)
                    }
                    _ => RelayMode::Default,
                };
                builder = builder.relay_mode(relay_mode);

                let iroh_dns_lookup = config.iroh_dns_domain.as_ref().map_or_else(
                    DnsAddressLookup::n0_dns,
                    |iroh_dns_domain| {
                        let iroh_dns_domain_clone = iroh_dns_domain.clone();
                        DnsAddressLookup::builder(iroh_dns_domain_clone)
                    },
                );
                builder = builder.address_lookup(iroh_dns_lookup);

                let iroh_pkarr_lookup = match &config.iroh_pkarr_relay {
                    Some(iroh_pkarr_relay) => {
                        let iroh_pkarr_relay_url = Url::parse(iroh_pkarr_relay)?;
                        PkarrPublisher::builder(iroh_pkarr_relay_url)
                    }
                    _ => PkarrPublisher::n0_dns(),
                };
                builder = builder.address_lookup(iroh_pkarr_lookup);

                builder.address_lookup(MdnsAddressLookup::builder().service_name(MDNS_SERVICE_NAME))
            }
        };

        // A fixed port makes this endpoint's direct address stable across restarts, so a
        // peer can dial it with `peer_addr` even when discovery is unavailable.
        let builder = if let Some(port) = config.bind_port {
            builder
                .clear_ip_transports()
                .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))?
                .bind_addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port))?
        } else {
            builder
        };

        let endpoint = builder.bind().await?;

        // In mDNS mode we register the lookup after binding so we keep a handle for discovery.
        let mdns = if config.mode() == Mode::Mdns {
            let lookup = MdnsAddressLookup::builder()
                .service_name(MDNS_SERVICE_NAME)
                .build(endpoint.id())
                .context("Failed to build mDNS address lookup")?;
            let services = endpoint
                .address_lookup()
                .context("Endpoint has no address lookup registry")?;
            services.add(lookup.clone());
            Some(lookup)
        } else {
            None
        };

        Ok((endpoint, my_passphrase, mdns))
    }

    fn get_keypair(base_dir: &BaseDir) -> (SecretKey, SecretKey) {
        let keyfile = base_dir.join(".teamtype").join("key");
        if keyfile.exists() {
            let metadata =
                fs::metadata(&keyfile).expect("Expected to have access to metadata of the keyfile");

            let current_permissions = metadata.permissions().mode();
            let allowed_permissions = 0o100_600;
            assert!(
                current_permissions == allowed_permissions,
                "For security reasons, please make sure to set the key file to user-readable only (set the permissions to 600)."
            );

            assert!(
                metadata.len() == 64,
                "Your keyfile is not 64 bytes long. This is a sign that it was created by a Teamtype version older than 0.7.0, which is not compatible. Please remove .teamtype/key, and try again."
            );

            debug!("Re-using existing keypair.");
            let mut file = File::open(keyfile).expect("Failed to open key file");

            let mut secret_key = [0; 32];
            file.read_exact(&mut secret_key)
                .expect("Failed to read from key file");

            let mut passphrase = [0; 32];
            file.read_exact(&mut passphrase)
                .expect("Failed to read from key file");

            (
                SecretKey::from_bytes(&secret_key),
                SecretKey::from_bytes(&passphrase),
            )
        } else {
            debug!("Generating new keypair.");
            let secret_key = SecretKey::generate();
            let passphrase = SecretKey::generate();

            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(keyfile)
                .expect("Should have been able to create key file that did not exist before");

            file.write_all(&secret_key.to_bytes())
                .expect("Failed to write to key file");
            file.write_all(&passphrase.to_bytes())
                .expect("Failed to write to key file");

            (secret_key, passphrase)
        }
    }
}

/// Derives this directory's long-term secret address (`endpoint_id#passphrase`) from the key
/// file, without starting a daemon.
#[expect(
    clippy::unnecessary_wraps,
    reason = "keeps a Result so callers can propagate key-loading errors if that becomes fallible"
)]
pub fn secret_address(base_dir: &BaseDir) -> Result<String> {
    let (secret_key, passphrase) = ConnectionManager::get_keypair(base_dir);
    Ok(format!(
        "{}#{}",
        secret_key.public(),
        data_encoding::HEXLOWER.encode(&passphrase.to_bytes())
    ))
}

enum EndpointMessage {
    // Instruct the endpoint to connect to a new peer.
    Connect {
        // All information we need to connect to another peer.
        secret_address: SecretAddress,
        // On connection success, this channel will be pinged.
        // Used for the initial connection, where we want to fail if connecting fails.
        response_tx: Option<oneshot::Sender<Result<()>>>,
        // Whether the host should reply with the long-term passphrase after auth.
        expect_reply: bool,
        // Whether to keep retrying after a failure.
        allow_reconnect: bool,
        // How many times have we already attempted to connect?
        previous_attempts: usize,
    },
}

// Owns the Iroh endpoint, accepts incoming connections, and can be instructed to connect to
// another daemon.
struct EndpointActor {
    endpoint: Endpoint,
    message_rx: mpsc::Receiver<EndpointMessage>,
    message_tx: mpsc::Sender<EndpointMessage>,
    document_handle: DocumentActorHandle,
    code_state: Arc<Mutex<CodeState>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    base_dir: BaseDir,
    ui: UserInterface,
}

impl EndpointActor {
    #[expect(
        clippy::too_many_arguments,
        reason = "actor wiring takes each collaborator explicitly"
    )]
    fn new(
        endpoint: Endpoint,
        message_rx: mpsc::Receiver<EndpointMessage>,
        message_tx: mpsc::Sender<EndpointMessage>,
        document_handle: DocumentActorHandle,
        code_state: Arc<Mutex<CodeState>>,
        rate_limiter: Arc<Mutex<RateLimiter>>,
        base_dir: BaseDir,
        ui: &UserInterface,
    ) -> Self {
        Self {
            endpoint,
            message_rx,
            message_tx,
            document_handle,
            code_state,
            rate_limiter,
            base_dir,
            ui: ui.clone(),
        }
    }

    async fn handle_message(&self, message: EndpointMessage) -> Result<()> {
        match message {
            EndpointMessage::Connect {
                secret_address,
                response_tx,
                expect_reply,
                allow_reconnect,
                previous_attempts,
            } => {
                let endpoint_addr = secret_address.endpoint_addr.clone();
                let connect_result = self.endpoint.connect(endpoint_addr, ALPN).await;
                let conn = match connect_result {
                    Ok(conn) => conn,
                    Err(err) => {
                        if let Some(response_tx) = response_tx {
                            response_tx
                                .send(Err(err.into()))
                                .expect("Connect receiver dropped");
                        }
                        if allow_reconnect {
                            Self::reconnect(
                                self.message_tx.clone(),
                                secret_address,
                                previous_attempts,
                                &self.ui,
                            )
                            .await
                            .expect("Failed to initiate reconnection");
                        }
                        // Not really Ok, but Ok enough.
                        return Ok(());
                    }
                };

                let endpoint_id = conn.remote_id();
                let auth = PeerAuth::Joiner {
                    credential: secret_address.passphrase.clone(),
                    expect_reply,
                };

                // Authenticate before reporting success, so a wrong invite code fails this
                // attempt and the caller can try the next candidate.
                let stream = match PeerMessageStream::new(conn.clone(), &auth).await {
                    Ok((stream, learned)) => {
                        if let Some(long_term) = learned {
                            let secret = format!(
                                "{}#{}",
                                endpoint_id,
                                data_encoding::HEXLOWER.encode(&long_term.to_bytes())
                            );
                            if let Err(err) =
                                crate::config::store_learned_peer(&self.base_dir, &secret, &self.ui)
                            {
                                debug!("Failed to store learned peer: {err:?}");
                            }
                        }
                        stream
                    }
                    Err(err) => {
                        if let Some(response_tx) = response_tx {
                            response_tx
                                .send(Err(err))
                                .expect("Connect receiver dropped");
                        }
                        if allow_reconnect {
                            Self::reconnect(
                                self.message_tx.clone(),
                                secret_address,
                                previous_attempts,
                                &self.ui,
                            )
                            .await
                            .expect("Failed to initiate reconnection");
                        }
                        return Ok(());
                    }
                };

                self.ui.inform(&format!("Connected to peer: {endpoint_id}"));
                if let Some(response_tx) = response_tx {
                    response_tx.send(Ok(())).expect("Connect receiver dropped");
                }

                let document_handle_clone = self.document_handle.clone();
                let message_tx_clone = self.message_tx.clone();
                tokio::spawn({
                    let ui = self.ui.clone();
                    async move {
                        Self::run_syncer(document_handle_clone, stream).await;
                        if allow_reconnect {
                            Self::reconnect(message_tx_clone, secret_address, 0, &ui)
                                .await
                                .expect("Failed to initiate reconnection");
                        }
                    }
                });
            }
        }
        Ok(())
    }

    async fn reconnect(
        message_tx: mpsc::Sender<EndpointMessage>,
        secret_address: SecretAddress,
        previous_attempts: usize,
        ui: &UserInterface,
    ) -> Result<()> {
        // Only log at "info" level if this is the first reconnection attempt.
        let endpoint_id = secret_address.endpoint_addr.id;
        if previous_attempts == 0 {
            ui.inform(&format!(
                "Connection to peer {endpoint_id} lost, will keep trying to reconnect..."
            ));
        } else {
            sleep(Duration::from_secs(10)).await;
            debug!("Making another attempt to connect to peer {endpoint_id}...");
        }
        // We don't need to be notified, so we don't need to use the response channel.
        message_tx
            .send(EndpointMessage::Connect {
                secret_address,
                response_tx: None,
                expect_reply: false,
                allow_reconnect: true,
                previous_attempts: previous_attempts + 1,
            })
            .await?;
        Ok(())
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                maybe_incoming = self.endpoint.accept() => {
                    match maybe_incoming {
                        Some(incoming) => {
                            let source = incoming.remote_addr();
                            match incoming.await {
                                Ok(conn) => {
                                    self.handle_incoming_connection(conn, source);
                                }
                                Err(err) => {
                                    debug!("Error while accepting peer connection: {err}");
                                }
                            }
                        }
                        None => {
                            // Endpoint was closed. Let's shut down.
                            break
                        }
                    }
                }
                maybe_message = self.message_rx.recv() => {
                    match maybe_message {
                        Some(message) => {
                            self.handle_message(message).await.expect("Failed to handle endpoint message");
                        }
                        None => {
                            // Our message channel was closed? Let's shut down.
                            break
                        }
                    }
                }
            }
        }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "the source address is produced here and not used elsewhere"
    )]
    fn handle_incoming_connection(&self, conn: IrohEndpointConnection, source: IncomingAddr) {
        let endpoint_id = conn.remote_id();

        let source_ip = match source {
            IncomingAddr::Ip(addr) => Some(addr.ip()),
            _ => None,
        };

        let code_state = self.code_state.clone();
        let rate_limiter = self.rate_limiter.clone();
        let document_handle_clone = self.document_handle.clone();
        tokio::spawn({
            let ui = self.ui.clone();
            async move {
                if let Some(ip) = source_ip
                    && rate_limiter.lock().await.is_banned(ip)
                {
                    ui.warn(&format!("Rejecting connection from banned source {ip}"));
                    return;
                }

                ui.inform(&format!("Peer connected: {endpoint_id}"));
                match PeerMessageStream::new(conn, &PeerAuth::Host(code_state.clone())).await {
                    Ok((stream, learned)) => {
                        if let Some(ip) = source_ip {
                            rate_limiter.lock().await.record_success(ip);
                        }
                        code_state.lock().await.on_success(learned.is_some());
                        Self::run_syncer(document_handle_clone, stream).await;
                    }
                    Err(err) => {
                        if let Some(ip) = source_ip {
                            rate_limiter.lock().await.record_failure(ip);
                        }
                        code_state.lock().await.on_failure();
                        ui.warn(&format!("Incoming connection failed: {err}"));
                    }
                }
                ui.inform(&format!("Peer disconnected: {endpoint_id}"));
            }
        });
    }

    async fn run_syncer(document_handle: DocumentActorHandle, stream: PeerMessageStream) {
        let syncer = SyncActor::new(document_handle, Box::new(stream));
        if let Err(err) = syncer.run().await {
            debug!("Error while syncing with peer: {err:?}");
        }
    }
}

// Sends/receives PeerMessages through an Iroh connection.
struct PeerMessageStream {
    send: SendStream,
    message_rx: mpsc::Receiver<Result<PeerMessage>>,
}

impl PeerMessageStream {
    async fn new(
        conn: IrohEndpointConnection,
        auth: &PeerAuth,
    ) -> Result<(Self, Option<SecretKey>)> {
        let mut learned = None;
        let (send, receive) = match auth {
            PeerAuth::Joiner {
                credential,
                expect_reply,
            } => {
                let (mut send, mut recv) = conn.open_bi().await?;
                send.write_all(&credential.to_bytes()).await?;
                if *expect_reply {
                    let mut received_passphrase = [0; 32];
                    recv.read_exact(&mut received_passphrase).await?;
                    learned = Some(SecretKey::from_bytes(&received_passphrase));
                }
                (send, recv)
            }
            PeerAuth::Host(state) => {
                let (mut send, mut recv) = conn.accept_bi().await?;

                let mut received_passphrase = [0; 32];
                recv.read_exact(&mut received_passphrase).await?;

                let credential = state.lock().await.check(&received_passphrase);
                match credential {
                    Some(Credential::LongTerm) => {}
                    Some(Credential::Code) => {
                        let long_term = state.lock().await.long_term().clone();
                        send.write_all(&long_term.to_bytes()).await?;
                        learned = Some(long_term);
                    }
                    None => bail!("Peer provided incorrect passphrase."),
                }

                (send, recv)
            }
        };

        let (message_tx, message_rx) = mpsc::channel(1);

        tokio::spawn(async move {
            let _ = Self::read_loop(receive, message_tx).await;
        });

        Ok((Self { send, message_rx }, learned))
    }

    async fn read_loop(
        mut receive: RecvStream,
        message_tx: mpsc::Sender<Result<PeerMessage>>,
    ) -> Result<()> {
        loop {
            let result = Self::read_next(&mut receive).await;

            message_tx.send(result).await?;
        }
    }

    async fn read_next(receive: &mut RecvStream) -> Result<PeerMessage> {
        let mut message_len_buf = [0; 4];
        receive.read_exact(&mut message_len_buf).await?;
        let byte_count = u32::from_be_bytes(message_len_buf);

        let mut bytes = vec![0; byte_count as usize];
        receive.read_exact(&mut bytes).await?;
        from_bytes(&bytes).context("Failed to convert bytes to PeerMessage")
    }
}

#[async_trait]
impl Connection<PeerMessage> for PeerMessageStream {
    async fn send(&mut self, message: PeerMessage) -> Result<()> {
        let bytes: Vec<u8> =
            to_allocvec(&message).context("Failed to convert PeerMessage to bytes")?;
        let byte_count =
            u32::try_from(bytes.len()).expect("Converting a length to u32 should work");

        self.send.write_all(&byte_count.to_be_bytes()).await?;
        self.send.write_all(&bytes).await?;

        Ok(())
    }

    async fn next(&mut self) -> Result<PeerMessage> {
        self.message_rx
            .recv()
            .await
            .context("Failed to await next peer message")?
    }
}
