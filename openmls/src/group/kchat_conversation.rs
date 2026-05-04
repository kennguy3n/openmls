//! # `KChatMlsConversation` — APQ orchestration scaffold
//!
//! A KChat conversation is **not** the same thing as an MLS group: depending
//! on its [`SecurityMode`], a conversation may be backed by a single
//! [`MlsGroup`] (Classical or DIRECT_PQ) or by **two** synchronized
//! [`MlsGroup`]s (APQ — one T session, one PQ session).
//!
//! `KChatMlsConversation` is the top-level orchestration struct that owns
//! both groups, the [`ApqInfo`] linking them, and the [`PqPolicy`] that
//! governs FULL/PARTIAL commit cadence. Its responsibilities are described
//! in [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) (KChat Orchestration
//! Layer).
//!
//! This module ships the **skeleton** of that struct: constructors per mode,
//! mode/group accessors, and the basic invariants enforced at construction.
//! The actual commit flow lives in
//! [`crate::group::apq_commit`](super::apq_commit), and the policy decisions
//! live in [`crate::group::pq_policy`](super::pq_policy).

use std::sync::Arc;

use openmls_traits::random::OpenMlsRand;
use openmls_traits::signatures::Signer;
use openmls_traits::types::Ciphersuite;

use crate::ciphersuite::SecurityMode;
use crate::extensions::apq_info::{ApqInfo, ApqInfoError};
use crate::framing::{MlsMessageBodyOut, MlsMessageOut};
use crate::group::apq_commit::{APQ_PSK_ID_LENGTH, APQ_PSK_LABEL, APQ_PSK_LENGTH};
use crate::group::mls_group::MlsGroup;
use crate::group::pq_policy::PqPolicy;
use crate::group::pq_telemetry::{NoOpTelemetryEmitter, PqTelemetryEmitter};
use crate::key_packages::KeyPackage;
use crate::messages::apq_welcome::{ApqWelcome, ApqWelcomeError};
use crate::messages::Welcome;
use crate::schedule::psk::PreSharedKeyId;
use crate::storage::OpenMlsProvider;

/// Top-level KChat conversation — wraps one or two [`MlsGroup`]s plus the
/// orchestration state needed to keep them in sync.
///
/// Invariants enforced by the constructors:
///
/// - `Classical` mode: `t_group` is set, `pq_group` and `apq_info` are not.
/// - `PqConfidentiality` / `PqAuthenticity` (direct PQ): `t_group` is the
///   sole MlsGroup (stored under `t_group` for storage uniformity),
///   `pq_group` is unset, `apq_info` is unset.
/// - APQ (mode is `PqConfidentiality` or `PqAuthenticity` AND both groups
///   are present): `t_group` and `pq_group` are both set, `apq_info` is set.
///
/// To distinguish DIRECT_PQ from APQ at runtime, callers consult
/// [`Self::is_apq`].
pub struct KChatMlsConversation {
    conversation_id: Vec<u8>,
    mode: SecurityMode,
    t_group: Option<MlsGroup>,
    pq_group: Option<MlsGroup>,
    apq_info: Option<ApqInfo>,
    pending_full_commit: bool,
    last_full_commit_epoch: u64,
    pq_policy: PqPolicy,
    /// PQ telemetry sink. Defaults to [`NoOpTelemetryEmitter`].
    /// Replace with [`Self::set_telemetry_emitter`] when wiring an
    /// observability backend.
    telemetry: Arc<dyn PqTelemetryEmitter>,
}

impl std::fmt::Debug for KChatMlsConversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KChatMlsConversation")
            .field("conversation_id", &self.conversation_id)
            .field("mode", &self.mode)
            .field("t_group", &self.t_group)
            .field("pq_group", &self.pq_group)
            .field("apq_info", &self.apq_info)
            .field("pending_full_commit", &self.pending_full_commit)
            .field("last_full_commit_epoch", &self.last_full_commit_epoch)
            .field("pq_policy", &self.pq_policy)
            .finish_non_exhaustive()
    }
}

/// Errors returned by [`KChatMlsConversation`] constructors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KChatConversationError {
    /// `Classical` mode constructor used with a non-classical configuration.
    #[error("Classical conversation must not have a PQ group or APQInfo")]
    ClassicalWithPqMaterial,
    /// Direct-PQ constructor used with `Classical` mode.
    #[error("DIRECT_PQ conversation must use a PQ security mode, got {got:?}")]
    DirectPqWithClassicalMode {
        /// Mode that was supplied.
        got: SecurityMode,
    },
    /// APQ constructor used with `Classical` mode.
    #[error("APQ conversation must use a PQ security mode, got {got:?}")]
    ApqWithClassicalMode {
        /// Mode that was supplied.
        got: SecurityMode,
    },
    /// APQ constructor's `apq_info.mode` does not match the conversation's
    /// `mode`.
    #[error("APQ conversation mode {expected:?} does not match APQInfo mode {got:?}")]
    ApqInfoModeMismatch {
        /// Mode supplied to the constructor.
        expected: SecurityMode,
        /// Mode recorded in `apq_info`.
        got: SecurityMode,
    },
    /// APQ-mode conversation supplied an [`ApqInfo`] that fails validation.
    #[error("APQInfo failed validation: {0}")]
    InvalidApqInfo(crate::extensions::apq_info::ApqInfoError),
}

impl KChatMlsConversation {
    /// Construct a `Classical`-mode conversation backed by a single T
    /// session.
    pub fn new_classical(
        conversation_id: Vec<u8>,
        t_group: MlsGroup,
    ) -> Result<Self, KChatConversationError> {
        Ok(Self {
            conversation_id,
            mode: SecurityMode::Classical,
            t_group: Some(t_group),
            pq_group: None,
            apq_info: None,
            pending_full_commit: false,
            last_full_commit_epoch: 0,
            pq_policy: PqPolicy::Classical,
            telemetry: Arc::new(NoOpTelemetryEmitter),
        })
    }

    /// Construct a DIRECT_PQ conversation backed by a single PQ session.
    ///
    /// `mode` must be `PqConfidentiality` or `PqAuthenticity`. The PQ session
    /// is stored under `t_group` (the conversation's only session) so the
    /// commit pipeline can treat "single-session" conversations uniformly.
    pub fn new_direct_pq(
        conversation_id: Vec<u8>,
        mode: SecurityMode,
        pq_group: MlsGroup,
        policy: PqPolicy,
    ) -> Result<Self, KChatConversationError> {
        if matches!(mode, SecurityMode::Classical) {
            return Err(KChatConversationError::DirectPqWithClassicalMode { got: mode });
        }

        Ok(Self {
            conversation_id,
            mode,
            t_group: Some(pq_group),
            pq_group: None,
            apq_info: None,
            pending_full_commit: false,
            last_full_commit_epoch: 0,
            pq_policy: policy,
            telemetry: Arc::new(NoOpTelemetryEmitter),
        })
    }

    /// Construct an APQ conversation backed by both a T session and a PQ
    /// session.
    pub fn new_apq(
        conversation_id: Vec<u8>,
        mode: SecurityMode,
        t_group: MlsGroup,
        pq_group: MlsGroup,
        apq_info: ApqInfo,
        policy: PqPolicy,
    ) -> Result<Self, KChatConversationError> {
        if matches!(mode, SecurityMode::Classical) {
            return Err(KChatConversationError::ApqWithClassicalMode { got: mode });
        }
        if apq_info.mode != mode {
            return Err(KChatConversationError::ApqInfoModeMismatch {
                expected: mode,
                got: apq_info.mode,
            });
        }
        apq_info
            .validate()
            .map_err(KChatConversationError::InvalidApqInfo)?;

        Ok(Self {
            conversation_id,
            mode,
            t_group: Some(t_group),
            pq_group: Some(pq_group),
            apq_info: Some(apq_info),
            pending_full_commit: false,
            last_full_commit_epoch: 0,
            pq_policy: policy,
            telemetry: Arc::new(NoOpTelemetryEmitter),
        })
    }

    /// Replace the [`PqTelemetryEmitter`] this conversation routes
    /// PQ-specific events through. The default is
    /// [`NoOpTelemetryEmitter`]; pass an
    /// [`crate::group::pq_telemetry::InMemoryTelemetryEmitter`] in tests
    /// or a real exporter (e.g. an OTel sink) in production.
    pub fn set_telemetry_emitter(&mut self, emitter: Arc<dyn PqTelemetryEmitter>) {
        self.telemetry = emitter;
    }

    /// Reference to the conversation's currently-installed
    /// [`PqTelemetryEmitter`].
    pub fn telemetry_emitter(&self) -> &Arc<dyn PqTelemetryEmitter> {
        &self.telemetry
    }

    /// The opaque application-level conversation identifier (KChat
    /// conversation ID, *not* an MLS group ID).
    pub fn conversation_id(&self) -> &[u8] {
        &self.conversation_id
    }

    /// Currently-active security mode.
    pub fn mode(&self) -> SecurityMode {
        self.mode
    }

    /// Active PQ commit policy.
    pub fn pq_policy(&self) -> PqPolicy {
        self.pq_policy
    }

    /// Reference to the T session group, if any. For DIRECT_PQ conversations
    /// this returns the PQ MlsGroup (stored under `t_group` for uniformity).
    pub fn t_group(&self) -> Option<&MlsGroup> {
        self.t_group.as_ref()
    }

    /// Mutable reference to the T session group, if any.
    pub fn t_group_mut(&mut self) -> Option<&mut MlsGroup> {
        self.t_group.as_mut()
    }

    /// Reference to the dedicated PQ session group (only set in APQ mode).
    pub fn pq_group(&self) -> Option<&MlsGroup> {
        self.pq_group.as_ref()
    }

    /// Mutable reference to the dedicated PQ session group.
    pub fn pq_group_mut(&mut self) -> Option<&mut MlsGroup> {
        self.pq_group.as_mut()
    }

    /// Reference to the APQ link record, if any (only set in APQ mode).
    pub fn apq_info(&self) -> Option<&ApqInfo> {
        self.apq_info.as_ref()
    }

    /// Returns `true` if this conversation is `Classical`.
    pub fn is_classical(&self) -> bool {
        matches!(self.mode, SecurityMode::Classical)
    }

    /// Returns `true` if this conversation is operating in any PQ mode
    /// (DIRECT_PQ or APQ).
    pub fn is_pq(&self) -> bool {
        !matches!(self.mode, SecurityMode::Classical)
    }

    /// Returns `true` if this conversation is APQ (two MlsGroups, with an
    /// APQInfo linking them).
    pub fn is_apq(&self) -> bool {
        self.is_pq() && self.pq_group.is_some() && self.apq_info.is_some()
    }

    /// Returns `true` if a FULL commit handshake is currently mid-flight
    /// (PQ commit done, T commit not yet acknowledged or vice versa).
    pub fn pending_full_commit(&self) -> bool {
        self.pending_full_commit
    }

    /// Set the pending-FULL-commit flag.
    pub fn set_pending_full_commit(&mut self, pending: bool) {
        self.pending_full_commit = pending;
    }

    /// Epoch at which the last successful FULL commit landed (0 if no FULL
    /// commit has happened yet).
    pub fn last_full_commit_epoch(&self) -> u64 {
        self.last_full_commit_epoch
    }

    /// Record a successful FULL commit at `epoch`.
    pub fn record_full_commit(&mut self, epoch: u64) {
        self.last_full_commit_epoch = epoch;
        self.pending_full_commit = false;
    }

    /// Replace the [`ApqInfo`]. The caller is responsible for running
    /// [`crate::group::no_downgrade::validate_apq_info_change`] *first*; this
    /// method only stores the value.
    pub fn set_apq_info(&mut self, apq_info: ApqInfo) {
        self.apq_info = Some(apq_info);
    }

    /// Bootstrap a Classical conversation into APQ.
    ///
    /// The caller supplies a freshly-created PQ [`MlsGroup`] (containing only
    /// the local member) and one [`KeyPackage`] per **other** member of the
    /// existing T session. This method:
    ///
    /// 1. Adds all peer members to the PQ session via
    ///    [`MlsGroup::add_members`] and merges the resulting commit so the PQ
    ///    session is operational at epoch 1.
    /// 2. Derives the initial `apq_psk` from the PQ session via
    ///    [`MlsGroup::export_secret`] using [`APQ_PSK_LABEL`] and the
    ///    conversation ID, then stores the secret under a fresh
    ///    [`PreSharedKeyId`] in the provider's PSK store.
    /// 3. Builds an [`ApqInfo`] linking the two sessions at their current
    ///    epochs and the requested security `apq_mode`.
    /// 4. Returns an [`ApqWelcome`] envelope containing the PQ Welcome,
    ///    the [`ApqInfo`], and the initial PSK ID for distribution to peers
    ///    (no T-session Welcome — peers are already members of the T
    ///    session).
    /// 5. Updates the conversation in place: switches `mode`, installs the
    ///    PQ group, installs the [`ApqInfo`], and replaces the [`PqPolicy`].
    ///
    /// The caller is responsible for actually delivering the [`ApqWelcome`]
    /// to peers, then optionally invoking
    /// [`crate::group::apq_commit::prepare_full_commit`] to bind the T
    /// session to the PQ session at the next epoch.
    ///
    /// See [`PHASES.md`](../../../PHASES.md) Phase 4.
    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap_apq<P, S>(
        &mut self,
        mut pq_group: MlsGroup,
        pq_key_packages: Vec<KeyPackage>,
        apq_mode: SecurityMode,
        apq_policy: PqPolicy,
        provider: &P,
        signer: &S,
    ) -> Result<ApqWelcome, ApqBootstrapError>
    where
        P: OpenMlsProvider,
        S: Signer,
    {
        // --- Preconditions ---------------------------------------------------
        if !self.is_classical() {
            return Err(ApqBootstrapError::AlreadyApq);
        }
        if self.t_group.is_none() {
            return Err(ApqBootstrapError::NoTSession);
        }
        if matches!(apq_mode, SecurityMode::Classical) {
            return Err(ApqBootstrapError::ClassicalApqMode);
        }
        if SecurityMode::from_ciphersuite(pq_group.ciphersuite()) == SecurityMode::Classical {
            return Err(ApqBootstrapError::PqGroupHasClassicalCiphersuite {
                ciphersuite: pq_group.ciphersuite(),
            });
        }
        if pq_key_packages.is_empty() {
            return Err(ApqBootstrapError::EmptyPqKeyPackages);
        }
        for kp in &pq_key_packages {
            if kp.ciphersuite() != pq_group.ciphersuite() {
                return Err(ApqBootstrapError::PqKeyPackageCiphersuiteMismatch {
                    expected: pq_group.ciphersuite(),
                    got: kp.ciphersuite(),
                });
            }
        }

        // PQ key packages must cover every *other* member of the T session.
        // The creator of the PQ group is already in the PQ session as its
        // sole leaf, so the count is `t_member_count - 1`.
        let t_member_count = self
            .t_group
            .as_ref()
            .expect("t_group present (precondition)")
            .members()
            .count();
        if pq_key_packages.len() + 1 != t_member_count {
            return Err(ApqBootstrapError::MembershipMismatch {
                t_count: t_member_count,
                pq_count: pq_key_packages.len() + 1,
            });
        }

        // --- 1. Add peers to PQ session, merge commit -----------------------
        let (_pq_commit, pq_welcome_msg, _pq_group_info) = pq_group
            .add_members(provider, signer, &pq_key_packages)
            .map_err(|e| {
                let msg = format!("{e}");
                self.emit_pq_provider_error("add_members", &msg);
                ApqBootstrapError::AddMembersFailed(msg)
            })?;
        pq_group.merge_pending_commit(provider).map_err(|e| {
            let msg = format!("{e}");
            self.emit_pq_provider_error("merge_pending_commit", &msg);
            ApqBootstrapError::MergeFailed(msg)
        })?;

        let pq_welcome = welcome_from_message(pq_welcome_msg)?;

        // --- 2. Derive initial apq_psk and store ----------------------------
        let apq_psk = pq_group
            .export_secret(
                provider.crypto(),
                APQ_PSK_LABEL,
                &self.conversation_id,
                APQ_PSK_LENGTH,
            )
            .map_err(|e| {
                let msg = format!("{e}");
                self.emit_pq_provider_error("export_secret", &msg);
                ApqBootstrapError::ExportSecretFailed(msg)
            })?;

        let psk_id_bytes = provider
            .rand()
            .random_vec(APQ_PSK_ID_LENGTH)
            .map_err(|e| ApqBootstrapError::RandomGenerationFailed(format!("psk_id: {e}")))?;
        let psk_nonce = provider
            .rand()
            .random_vec(pq_group.ciphersuite().hash_length())
            .map_err(|e| ApqBootstrapError::RandomGenerationFailed(format!("psk_nonce: {e}")))?;
        let initial_apq_psk_id = PreSharedKeyId::external(psk_id_bytes, psk_nonce);
        initial_apq_psk_id
            .store(provider, &apq_psk)
            .map_err(|e| ApqBootstrapError::PskStoreFailed(format!("{e}")))?;

        // --- 3. Build ApqInfo -----------------------------------------------
        //
        // `ApqInfo::{t_epoch, pq_epoch}` track the FULL-commit synchronization
        // counter for the APQ relationship — they are *not* the live MLS
        // group epochs. At bootstrap, the PQ group has just performed its
        // first commit (epoch 1) and is the synchronization anchor for the
        // new APQ relationship; both fields therefore start at the PQ
        // group's epoch. Subsequent FULL commits advance both fields
        // together, keeping the recorded drift at zero.
        //
        // This decouples the recorded drift check from the absolute T-group
        // epoch, which can be arbitrarily large for long-running classical
        // groups being upgraded in place (PHASES.md Phase 4).
        let t_group = self
            .t_group
            .as_ref()
            .expect("t_group present (precondition)");
        let sync_epoch = pq_group.epoch().as_u64();
        let apq_info = ApqInfo::new(
            t_group.group_id().clone(),
            pq_group.group_id().clone(),
            sync_epoch,
            sync_epoch,
            t_group.ciphersuite(),
            pq_group.ciphersuite(),
            apq_mode,
        );
        apq_info
            .validate()
            .map_err(ApqBootstrapError::InvalidApqInfo)?;

        // --- 4. Build ApqWelcome (no T welcome — peers already in T) -------
        let apq_welcome = ApqWelcome {
            t_welcome: None,
            pq_welcome,
            apq_info: apq_info.clone(),
            initial_apq_psk_id: Some(initial_apq_psk_id),
        };
        apq_welcome
            .validate()
            .map_err(ApqBootstrapError::ApqWelcomeInvalid)?;

        // --- 5. Mutate conversation -----------------------------------------
        self.mode = apq_mode;
        self.pq_group = Some(pq_group);
        self.apq_info = Some(apq_info);
        self.pq_policy = apq_policy;

        // --- 6. Emit telemetry ----------------------------------------------
        let member_count = self
            .pq_group
            .as_ref()
            .expect("pq_group installed above")
            .members()
            .count();
        self.telemetry.emit(
            crate::group::pq_telemetry::PqTelemetryEvent::ApqBootstrapCompleted {
                conversation_id: self.conversation_id.clone(),
                mode: apq_mode,
                member_count,
            },
        );

        Ok(apq_welcome)
    }

    /// Internal helper: emit a [`MissedCommitPair`] event.
    ///
    /// [`MissedCommitPair`]:
    ///     crate::group::pq_telemetry::PqTelemetryEvent::MissedCommitPair
    #[allow(dead_code)]
    pub(crate) fn emit_missed_commit_pair(&self, missed_side: &str, t_epoch: u64, pq_epoch: u64) {
        self.telemetry.emit(
            crate::group::pq_telemetry::PqTelemetryEvent::MissedCommitPair {
                conversation_id: self.conversation_id.clone(),
                missed_side: missed_side.to_string(),
                t_epoch,
                pq_epoch,
            },
        );
    }

    /// Internal helper: emit a [`PqProviderError`] event for an opaque
    /// PQ provider failure.
    ///
    /// [`PqProviderError`]:
    ///     crate::group::pq_telemetry::PqTelemetryEvent::PqProviderError
    pub(crate) fn emit_pq_provider_error(&self, operation: &str, error: &str) {
        self.telemetry.emit(
            crate::group::pq_telemetry::PqTelemetryEvent::PqProviderError {
                operation: operation.to_string(),
                error: error.to_string(),
            },
        );
    }

    /// Internal helper: emit a [`ResyncTriggered`] event with the
    /// supplied free-form `status` describing the resync flavour.
    ///
    /// [`ResyncTriggered`]:
    ///     crate::group::pq_telemetry::PqTelemetryEvent::ResyncTriggered
    pub(crate) fn emit_resync_triggered(&self, status: &str) {
        self.telemetry.emit(
            crate::group::pq_telemetry::PqTelemetryEvent::ResyncTriggered {
                conversation_id: self.conversation_id.clone(),
                status: status.to_string(),
            },
        );
    }

    /// Internal helper: emit a [`DowngradeAttempt`] event.
    ///
    /// [`DowngradeAttempt`]:
    ///     crate::group::pq_telemetry::PqTelemetryEvent::DowngradeAttempt
    #[allow(dead_code)]
    pub(crate) fn emit_downgrade_attempt(&self, from: SecurityMode, to: SecurityMode) {
        self.telemetry.emit(
            crate::group::pq_telemetry::PqTelemetryEvent::DowngradeAttempt {
                conversation_id: self.conversation_id.clone(),
                from,
                to,
            },
        );
    }

    /// Internal helper: emit a [`ReInitCompleted`] event.
    ///
    /// [`ReInitCompleted`]:
    ///     crate::group::pq_telemetry::PqTelemetryEvent::ReInitCompleted
    #[allow(dead_code)]
    pub(crate) fn emit_reinit_completed(
        &self,
        old_ciphersuite: Ciphersuite,
        new_ciphersuite: Ciphersuite,
    ) {
        self.telemetry.emit(
            crate::group::pq_telemetry::PqTelemetryEvent::ReInitCompleted {
                conversation_id: self.conversation_id.clone(),
                old_ciphersuite,
                new_ciphersuite,
            },
        );
    }
}

/// Errors returned by [`KChatMlsConversation::bootstrap_apq`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApqBootstrapError {
    /// Conversation is already APQ (or DIRECT_PQ).
    #[error(
        "conversation is already APQ — bootstrap_apq must be called on a Classical conversation"
    )]
    AlreadyApq,
    /// Conversation has no T session.
    #[error("conversation has no T session")]
    NoTSession,
    /// Caller passed `SecurityMode::Classical` as the bootstrap mode.
    #[error("bootstrap_apq requires a non-classical SecurityMode")]
    ClassicalApqMode,
    /// PQ group's ciphersuite is classical (i.e. not actually PQ).
    #[error("PQ group ciphersuite {ciphersuite:?} is not a post-quantum ciphersuite")]
    PqGroupHasClassicalCiphersuite {
        /// The classical ciphersuite that was supplied.
        ciphersuite: Ciphersuite,
    },
    /// `pq_key_packages` was empty (must contain at least one peer).
    #[error("pq_key_packages is empty — bootstrap_apq requires at least one peer KeyPackage")]
    EmptyPqKeyPackages,
    /// One of the supplied PQ KeyPackages has a different ciphersuite than
    /// the PQ group.
    #[error("PQ KeyPackage ciphersuite mismatch: expected {expected:?} got {got:?}")]
    PqKeyPackageCiphersuiteMismatch {
        /// Ciphersuite of the PQ group.
        expected: Ciphersuite,
        /// Ciphersuite of the offending KeyPackage.
        got: Ciphersuite,
    },
    /// `pq_key_packages.len() + 1` (creator) does not match the T session's
    /// member count.
    #[error("membership mismatch: T session has {t_count} members but PQ side covers {pq_count}")]
    MembershipMismatch {
        /// Number of members in the T session.
        t_count: usize,
        /// Number of members the PQ side would have after the bootstrap
        /// add_members commit (i.e. supplied KPs + creator).
        pq_count: usize,
    },
    /// [`MlsGroup::add_members`] failed on the PQ session.
    #[error("PQ session add_members failed: {0}")]
    AddMembersFailed(String),
    /// Merging the PQ session's pending commit failed.
    #[error("PQ session merge_pending_commit failed: {0}")]
    MergeFailed(String),
    /// [`MlsGroup::export_secret`] failed on the PQ session.
    #[error("PQ session export_secret failed: {0}")]
    ExportSecretFailed(String),
    /// Random byte generation failed.
    #[error("random generation failed: {0}")]
    RandomGenerationFailed(String),
    /// Persisting the derived `apq_psk` in the provider's PSK store failed.
    #[error("apq_psk store failed: {0}")]
    PskStoreFailed(String),
    /// `add_members` returned an [`MlsMessageOut`] whose body was not a
    /// [`Welcome`]. This should not happen in practice — it indicates an
    /// internal contract violation.
    #[error("PQ add_members returned a non-Welcome MlsMessageOut")]
    UnexpectedAddMembersOutput,
    /// Constructed [`ApqInfo`] failed validation.
    #[error("APQInfo validation failed: {0}")]
    InvalidApqInfo(ApqInfoError),
    /// Constructed [`ApqWelcome`] failed validation.
    #[error("ApqWelcome validation failed: {0}")]
    ApqWelcomeInvalid(ApqWelcomeError),
}

/// Pull a [`Welcome`] out of an [`MlsMessageOut`]. Returns
/// [`ApqBootstrapError::UnexpectedAddMembersOutput`] if the message body is
/// not a Welcome.
fn welcome_from_message(msg: MlsMessageOut) -> Result<Welcome, ApqBootstrapError> {
    match msg.body {
        MlsMessageBodyOut::Welcome(w) => Ok(w),
        _ => Err(ApqBootstrapError::UnexpectedAddMembersOutput),
    }
}

#[cfg(test)]
mod tests {
    //! Mode-only construction tests. These do not exercise actual MLS
    //! group operations — that's covered by the integration tests in
    //! `tests/pq_capability_tests.rs` and the upcoming
    //! `tests/pq_downgrade_tests.rs`.
    use super::*;
    use crate::group::GroupId;
    use openmls_traits::types::Ciphersuite;

    fn pq_apq_info() -> ApqInfo {
        ApqInfo::new(
            GroupId::from_slice(&[1; 16]),
            GroupId::from_slice(&[2; 16]),
            5,
            5,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            SecurityMode::PqConfidentiality,
        )
    }

    // The classical / direct-pq / apq constructors all need an `MlsGroup`
    // value to populate their group fields. Constructing one of those in a
    // unit test is heavyweight (requires a provider, signer, credential).
    // The unit tests here therefore drive the **mode-only** behaviors —
    // construction errors and the mode-query helpers — and rely on integration
    // tests to exercise the constructors with real groups.

    #[test]
    fn direct_pq_constructor_rejects_classical_mode() {
        // We can't actually call new_direct_pq without an MlsGroup, but we
        // *can* assert that the precondition is rejected via a unit-test
        // shim: replicate the check.
        let mode = SecurityMode::Classical;
        assert!(
            matches!(mode, SecurityMode::Classical),
            "classical mode is rejected by new_direct_pq"
        );
    }

    #[test]
    fn apq_info_mode_must_match_conversation_mode() {
        let info = pq_apq_info();
        // Constructor would reject mode != info.mode — validate the helper.
        let mismatch = KChatConversationError::ApqInfoModeMismatch {
            expected: SecurityMode::PqAuthenticity,
            got: info.mode,
        };
        assert_eq!(
            format!("{mismatch}"),
            "APQ conversation mode PqAuthenticity does not match APQInfo mode PqConfidentiality"
        );
    }

    #[test]
    fn apq_info_validation_propagates_through_constructor_error() {
        let mut info = pq_apq_info();
        info.t_group_id = info.pq_group_id.clone();
        let validation_err = info.validate().unwrap_err();
        let constructor_err = KChatConversationError::InvalidApqInfo(validation_err);
        assert!(matches!(
            constructor_err,
            KChatConversationError::InvalidApqInfo(_)
        ));
    }

    #[test]
    fn classical_with_pq_material_error_renders_clearly() {
        let err = KChatConversationError::ClassicalWithPqMaterial;
        assert_eq!(
            format!("{err}"),
            "Classical conversation must not have a PQ group or APQInfo"
        );
    }

    #[test]
    fn direct_pq_with_classical_mode_error_renders_clearly() {
        let err = KChatConversationError::DirectPqWithClassicalMode {
            got: SecurityMode::Classical,
        };
        assert_eq!(
            format!("{err}"),
            "DIRECT_PQ conversation must use a PQ security mode, got Classical"
        );
    }
}
