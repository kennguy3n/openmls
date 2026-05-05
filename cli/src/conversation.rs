use openmls::ciphersuite::security_mode::SecurityMode;
use openmls::prelude::Ciphersuite;
use serde::{Deserialize, Serialize};

/// PQ-mode requested when creating a conversation from the CLI.
///
/// Mirrors [`openmls::ciphersuite::security_mode::SecurityMode`] but is
/// used for command-line parsing so we can give friendly error messages
/// independent of MLS internals.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CliSecurityMode {
    /// Classical-only (RFC 9420 ciphersuites). Default.
    Classical,
    /// Hybrid KEM + classical signatures (X-Wing + Ed25519).
    PqConfidentiality,
    /// PQ KEM + PQ signatures (X-Wing + ML-DSA-65).
    PqAuthenticity,
}

impl CliSecurityMode {
    /// Parse `--security-mode` value or trailing keyword on `create group`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "classical" | "default" | "" => Ok(Self::Classical),
            "pq-confidentiality" | "pq_confidentiality" | "pq-conf" | "confidentiality" => {
                Ok(Self::PqConfidentiality)
            }
            "pq-authenticity" | "pq_authenticity" | "pq-auth" | "authenticity" => {
                Ok(Self::PqAuthenticity)
            }
            other => Err(format!(
                "unknown security mode {other:?} (expected one of \
                 classical, pq-confidentiality, pq-authenticity)"
            )),
        }
    }

    /// Lift the CLI mode into the internal [`SecurityMode`] enum.
    pub fn to_security_mode(self) -> SecurityMode {
        match self {
            Self::Classical => SecurityMode::Classical,
            Self::PqConfidentiality => SecurityMode::PqConfidentiality,
            Self::PqAuthenticity => SecurityMode::PqAuthenticity,
        }
    }

    /// Pick the canonical ciphersuite the CLI uses for a given mode.
    ///
    /// - [`Self::Classical`] — RFC 9420 X25519 + Ed25519 suite, always
    ///   available.
    /// - [`Self::PqConfidentiality`] — X-Wing KEM + Ed25519 signatures,
    ///   gated behind `--features xwing`. Provides post-quantum
    ///   confidentiality but classical-strength authenticity.
    /// - [`Self::PqAuthenticity`] — ML-KEM-768 + ML-DSA-65 signatures
    ///   (codepoint `0xFE05`), gated behind `--features mldsa`.
    ///   Provides PQ confidentiality **and** PQ authenticity.
    ///
    /// The two PQ arms are kept distinct so a user who asked for
    /// `pq-authenticity` is never silently downgraded to a classically
    /// signed ciphersuite. If the required feature is not enabled at
    /// build time the function returns a clear, actionable error
    /// instead of falling back to a weaker mode.
    pub fn default_ciphersuite(self) -> Result<Ciphersuite, String> {
        match self {
            Self::Classical => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            Self::PqConfidentiality => {
                #[cfg(feature = "xwing")]
                {
                    Ok(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
                }
                #[cfg(not(feature = "xwing"))]
                {
                    Err(
                        "PqConfidentiality mode requires the `xwing` feature on `cli` \
                         (rebuild with `cargo run -p cli --features xwing`)"
                            .to_string(),
                    )
                }
            }
            Self::PqAuthenticity => {
                // PqAuthenticity must use an ML-DSA-signed ciphersuite —
                // X-Wing alone only provides PQ confidentiality (its
                // signatures are still Ed25519). Falling back to the
                // X-Wing suite here would silently mis-label the
                // resulting group as `PqAuthenticity` while delivering
                // only `PqConfidentiality`.
                #[cfg(feature = "mldsa")]
                {
                    Ok(Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65)
                }
                #[cfg(not(feature = "mldsa"))]
                {
                    Err("PqAuthenticity mode requires the `mldsa` feature on `cli` \
                         (rebuild with `cargo run -p cli --features mldsa`); \
                         falling back to PqConfidentiality would silently mis-label \
                         the conversation"
                        .to_string())
                }
            }
        }
    }
}

/// A conversation is a list of messages (strings).
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Conversation {
    messages: Vec<ConversationMessage>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ConversationMessage {
    pub author: String,
    pub message: String,
}

impl Conversation {
    /// Add a message string to the conversation list.
    pub fn add(&mut self, conversation_message: ConversationMessage) {
        self.messages.push(conversation_message)
    }

    /// Get a list of messages in the conversation.
    /// The function returns the `last_n` messages.
    #[allow(dead_code)]
    pub fn get(&self, last_n: usize) -> Option<&[ConversationMessage]> {
        let num_messages = self.messages.len();
        let start = num_messages.saturating_sub(last_n);
        self.messages.get(start..num_messages)
    }
}

impl ConversationMessage {
    pub fn new(message: String, author: String) -> Self {
        Self { author, message }
    }
}
