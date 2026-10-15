// SPDX-FileCopyrightText: 2025 blinry <mail@blinry.org>
// SPDX-FileCopyrightText: 2025 zormit <nt4u@kpvn.de>
// SPDX-FileCopyrightText: 2026 Caleb Maclennan <caleb@alerque.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{borrow::Cow, str::FromStr, time::Duration};

use anyhow::Result;
use docstr::docstr;
use magic_wormhole::{AppConfig, AppID, Code, MailboxConnection, Password, Wormhole, transfer};
use rand::seq::IteratorRandom;
use tokio::time::sleep;

const NETWORK_RETRY: Duration = Duration::from_mins(5);
/// How often `rotate_code = periodic` replaces a Magic Wormhole mailbox.
const MW_ROTATE_PERIOD: Duration = Duration::from_mins(10);

use crate::config::RotateCode;
use crate::types::UserInterface;

/// Picks a random `adjective-noun` Magic Wormhole password.
fn random_password(adjectives: &[&str], nouns: &[&str]) -> Password {
    let adjective = adjectives
        .iter()
        .choose(&mut rand::rng())
        .expect("Word list cannot be empty");
    let noun = nouns
        .iter()
        .choose(&mut rand::rng())
        .expect("Word list cannot be empty");
    format!("{adjective}-{noun}")
        .parse()
        .expect("Password must be long enough and have enough entropy")
}

pub async fn put_secret_address_into_wormhole(
    address: &str,
    magic_wormhole_relay: Option<String>,
    rotate: RotateCode,
    ui: &UserInterface,
) {
    let payload: Vec<u8> = address.into();
    let config = build_magic_wormhole_config(magic_wormhole_relay, ui);

    let adjectives: Vec<&str> = include_str!("../assets/adjectives.txt").lines().collect();
    let nouns: Vec<&str> = include_str!("../assets/nouns.txt").lines().collect();

    tokio::spawn({
        let ui = ui.clone();
        async move {
            // `never` reuses a single password, so the join code stays stable.
            let fixed_password =
                (rotate == RotateCode::Never).then(|| random_password(&adjectives, &nouns));
            loop {
                let password = fixed_password
                    .clone()
                    .unwrap_or_else(|| random_password(&adjectives, &nouns));

                let Ok(mailbox_connection) =
                    MailboxConnection::create_with_password(config.clone(), password).await
                else {
                    ui.warn(&format!(
                            "Failed to register a new join code via Magic Wormhole. Automatic retry in {NETWORK_RETRY:?}. Peers who joined before can still re-connect without a code.",
                        ));
                    sleep(NETWORK_RETRY).await;
                    continue;
                };
                let code = mailbox_connection.code().clone();

                ui.inform(&docstr!(format!
                        /// One other person can use this to connect to you:
                        ///
                        ///    teamtype join {code}
                        ///
                ));

                // `periodic` bounds how long a mailbox waits for a peer before the code is
                // replaced; the other policies simply wait for a peer to arrive.
                let connected = match rotate {
                    RotateCode::Periodic => {
                        match tokio::time::timeout(
                            MW_ROTATE_PERIOD,
                            Wormhole::connect(mailbox_connection),
                        )
                        .await
                        {
                            Ok(Ok(wormhole)) => Some(wormhole),
                            _ => None,
                        }
                    }
                    _ => Wormhole::connect(mailbox_connection).await.ok(),
                };

                if let Some(mut wormhole) = connected {
                    let _ = wormhole.send(payload.clone()).await;
                } else {
                    ui.warn("Failed to share secret address. Did your peer mistype the join code?");
                }

                if rotate == RotateCode::Continuous {
                    // Keep offering fresh mailboxes without waiting.
                    continue;
                }

                // Print a new join code in the next iteration, to allow more people to join.
                sleep(Duration::from_millis(500)).await;
            }
        }
    });
}

pub async fn get_secret_address_from_wormhole(
    code: &str,
    magic_wormhole_relay: Option<String>,
    ui: &UserInterface,
) -> Result<String> {
    let config = build_magic_wormhole_config(magic_wormhole_relay, ui);

    let mut wormhole =
        Wormhole::connect(MailboxConnection::connect(config, Code::from_str(code)?, false).await?)
            .await?;
    let bytes = wormhole.receive().await?;
    Ok(String::from_utf8(bytes)?)
}

fn build_magic_wormhole_config(
    magic_wormhole_relay: Option<String>,
    ui: &UserInterface,
) -> AppConfig<transfer::AppVersion> {
    let mut config = transfer::APP_CONFIG.id(AppID::new("teamtype"));

    if let Some(url) = magic_wormhole_relay {
        ui.log(&format!("Using non-default Magic Wormhole relay url {url}"));
        config = config.rendezvous_url(Cow::Owned(url));
    }
    config
}
