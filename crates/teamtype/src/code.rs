// SPDX-FileCopyrightText: 2026 Teamtype contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Human-transcribable invite codes.
//!
//! A code is a short sequence of words from the BIP39 English list, prefixed with `tt-` so it
//! can be told apart from a Magic Wormhole join code. The words are not the credential: the
//! actual key is derived from the code together with the host's endpoint id, so a code that
//! leaks to one host is useless against another.

use anyhow::Result;
use hkdf::Hkdf;
use rand::seq::IteratorRandom;
use sha2::Sha256;

/// Prefix identifying a Teamtype invite code.
pub const CODE_PREFIX: &str = "tt";
/// Number of words in a generated code. 4 words is ~44 bits of entropy.
pub const CODE_WORDS: usize = 4;
/// Context string mixed into the KDF.
const KDF_INFO: &[u8] = b"teamtype/invite-code/v1";

const WORD_LIST: &str = include_str!("../assets/bip39-english.txt");

/// Returns all words in the bundled word list.
pub fn words() -> impl Iterator<Item = &'static str> {
    WORD_LIST.lines()
}

/// Whether `word` is in the bundled word list.
#[must_use]
pub fn is_known_word(word: &str) -> bool {
    WORD_LIST.lines().any(|w| w == word)
}

/// Generates a fresh `tt-…` invite code.
pub fn generate() -> String {
    let list: Vec<&str> = WORD_LIST.lines().collect();
    let mut rng = rand::rng();
    let chosen: Vec<&str> = std::iter::repeat_with(|| {
        list.iter()
            .choose(&mut rng)
            .copied()
            .expect("word list is not empty")
    })
    .take(CODE_WORDS)
    .collect();
    format!("{CODE_PREFIX}-{}", chosen.join("-"))
}

/// Normalizes user input into canonical code form: lowercase, with `-` separators.
#[must_use]
pub fn normalize(input: &str) -> String {
    input
        .trim()
        .to_ascii_lowercase()
        .split(['-', ' ', '_'])
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Whether `input` looks like a Teamtype invite code.
#[must_use]
pub fn is_code(input: &str) -> bool {
    normalize(input).starts_with(&format!("{CODE_PREFIX}-"))
}

/// The words of a code, without the `tt-` prefix.
#[must_use]
pub fn code_words(code: &str) -> Vec<String> {
    normalize(code)
        .split('-')
        .skip(1)
        .map(ToString::to_string)
        .collect()
}

/// Derives the 32-byte credential from a code and the host's endpoint id.
///
/// The endpoint id is used as the HKDF salt, so the same code yields different keys for
/// different hosts. This is what makes it safe to try a code against every discovered host.
pub fn derive_key(code: &str, endpoint_id: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(endpoint_id), normalize(code).as_bytes());
    let mut out = [0u8; 32];
    hk.expand(KDF_INFO, &mut out)
        .map_err(|_| anyhow::anyhow!("Failed to expand HKDF for invite code"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_expected_shape() {
        let code = generate();
        assert!(code.starts_with("tt-"));
        assert_eq!(code_words(&code).len(), CODE_WORDS);
        assert!(code_words(&code).iter().all(|w| is_known_word(w)));
    }

    #[test]
    fn normalizes_input() {
        assert_eq!(
            normalize(" TT-Otter Basil_lantern  sun "),
            "tt-otter-basil-lantern-sun"
        );
    }

    #[test]
    fn recognises_codes() {
        assert!(is_code("tt-otter-basil-lantern-sun"));
        assert!(!is_code("3-exhausted-bananas"));
    }

    #[test]
    fn derivation_is_deterministic_and_salted() -> Result<()> {
        let id_a = [1u8; 32];
        let id_b = [2u8; 32];
        let k1 = derive_key("tt-a-b-c-d", &id_a)?;
        let k2 = derive_key("tt-a-b-c-d", &id_a)?;
        let k3 = derive_key("tt-a-b-c-d", &id_b)?;
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_eq!(k1.len(), 32);
        Ok(())
    }
}
