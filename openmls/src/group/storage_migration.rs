//! # Idempotent client-side storage migration
//!
//! KChat clients ship a cumulative storage schema: each release that adds a
//! new field, table, or invariant is paired with a migration step that
//! brings older on-disk state forward. The orchestration layer **must** be
//! safe to run repeatedly — a client can be upgraded, crash mid-migration,
//! and re-run the migration safely on next start (see
//! [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) §Storage Requirements).
//!
//! This module is the storage-agnostic driver for that workflow. It exposes:
//!
//! - [`StorageMigrationState`] — persistent progress marker with four
//!   variants: `NotStarted`, `InProgress(step)`, `Complete`, `Failed`.
//! - [`MigrationStep`] — the ordered list of steps for the current
//!   schema version.
//! - [`MigrationStorage`] — the trait that concrete storage backends
//!   (SQLite, Sled, in-memory test doubles) implement to plug into the
//!   [`StorageMigrator`] driver.
//! - [`StorageMigrator`] — the driver that reads state, runs each step
//!   idempotently with a check-before-write pattern, and persists
//!   progress after every step.
//!
//! The migrator never assumes a particular durability semantics from the
//! storage — it always re-checks state on entry and after each step, so a
//! crash *between* `migrate_*` and `persist_state` simply re-runs the same
//! step on next boot, which is by definition a no-op once the underlying
//! data has been written.

use serde::{Deserialize, Serialize};

/// One ordered step in the client storage migration plan.
///
/// New steps may be appended to the end of this enum **only** — reordering
/// or removing a variant would invalidate already-persisted
/// [`StorageMigrationState::InProgress`] markers.
///
/// Each variant maps to a `MigrationStorage::migrate_*` and a
/// `MigrationStorage::*_present` validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MigrationStep {
    /// Migrate the per-group MLS state (group context, ratchet tree,
    /// epoch secrets) to the current schema.
    MigrateGroupState,
    /// Migrate the [`crate::extensions::apq_info::ApqInfo`] linkage
    /// records used by APQ conversations.
    MigrateApqInfo,
    /// Migrate the application-level (conversation_id → MLS group id)
    /// mapping table used by the orchestration layer.
    MigrateConversationMapping,
    /// Migrate persisted PSK material (apq_psk bundles, external PSKs).
    MigratePskMaterial,
    /// Migrate per-conversation FULL/PARTIAL commit counters used by the
    /// [`crate::group::pq_policy`] cadence checker.
    MigrateCommitCounters,
    /// Migrate the [`crate::group::no_downgrade::ConversationSecurityState`]
    /// snapshots used by the anti-downgrade validator.
    MigrateAntiDowngradeState,
}

impl MigrationStep {
    /// Ordered list of every step in the migration plan, in the order
    /// they must run.
    pub const ALL: &'static [MigrationStep] = &[
        MigrationStep::MigrateGroupState,
        MigrationStep::MigrateApqInfo,
        MigrationStep::MigrateConversationMapping,
        MigrationStep::MigratePskMaterial,
        MigrationStep::MigrateCommitCounters,
        MigrationStep::MigrateAntiDowngradeState,
    ];

    /// Index of this step in [`MigrationStep::ALL`].
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    /// Step that follows `self` in the migration plan, or `None` if
    /// `self` is the last one.
    pub fn next(self) -> Option<MigrationStep> {
        Self::ALL.get(self.index() + 1).copied()
    }
}

/// Persistent progress marker for the storage migrator.
///
/// `InProgress(step)` always names the *next* step the migrator should
/// run — i.e. once a step finishes successfully, the migrator advances
/// the marker to `InProgress(next_step)` and persists it before running
/// `next_step`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageMigrationState {
    /// No migration has been attempted yet.
    NotStarted,
    /// The migration is partway through; `step` is the next step to run.
    InProgress(MigrationStep),
    /// Every step has run to completion.
    Complete,
    /// The migration aborted with the carried human-readable reason. The
    /// storage may be in a partially-migrated state and must be repaired
    /// before another `run_migration` call.
    Failed(String),
}

impl StorageMigrationState {
    /// Returns `true` if the migration is in a terminal state
    /// (`Complete` or `Failed`).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            StorageMigrationState::Complete | StorageMigrationState::Failed(_)
        )
    }
}

/// Errors raised by [`StorageMigrator::run_migration`] /
/// [`StorageMigrator::validate_post_migration`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrationError {
    /// A specific migration step failed. The migrator persists
    /// `Failed(reason)` before returning so the next start does not
    /// silently retry a broken step.
    #[error("step {step:?} failed: {reason}")]
    StepFailed {
        /// The step that failed.
        step: MigrationStep,
        /// Human-readable reason.
        reason: String,
    },
    /// Persisting the [`StorageMigrationState`] marker itself failed.
    /// The on-disk schema is now in an undefined state and the migrator
    /// stops without trying to run further steps.
    #[error("persisting migration state failed: {reason}")]
    PersistenceFailed {
        /// Reason supplied by the storage layer.
        reason: String,
    },
    /// `run_migration` was called on a backend whose state is `Failed(_)`.
    /// Callers must repair / clear the underlying storage before
    /// retrying.
    #[error("migration is in Failed state: {reason}")]
    PreviouslyFailed {
        /// Reason carried by the previous failure marker.
        reason: String,
    },
}

/// Errors raised by [`StorageMigrator::validate_post_migration`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrationValidationError {
    /// The migration has not finished yet — `state` is the current
    /// marker.
    #[error("migration not complete: {state:?}")]
    NotComplete {
        /// Current persisted state.
        state: StorageMigrationState,
    },
    /// A specific step's invariant is broken — its target state is
    /// missing despite the migrator marking the migration `Complete`.
    #[error("post-migration invariant broken: step {step:?}")]
    InvariantBroken {
        /// The step whose post-condition is missing.
        step: MigrationStep,
    },
}

/// Storage backend implemented by clients of [`StorageMigrator`].
///
/// Each `migrate_*` is responsible for its own idempotency — the
/// migrator calls it on every visit (fresh boot or resume after crash);
/// the implementation must read the existing state and write only what
/// is missing. The corresponding `*_present` accessor is used by
/// [`StorageMigrator::validate_post_migration`] to confirm the
/// post-condition holds.
pub trait MigrationStorage {
    /// Read the persisted [`StorageMigrationState`]. A fresh / clean
    /// store should return [`StorageMigrationState::NotStarted`].
    fn read_state(&self) -> StorageMigrationState;

    /// Persist `state`. Implementations should treat this as a fsync /
    /// flush — the migrator relies on the marker being durable before
    /// running the next step.
    fn persist_state(&mut self, state: &StorageMigrationState) -> Result<(), String>;

    /// Idempotently bring on-disk MLS group state to the current schema.
    fn migrate_group_state(&mut self) -> Result<(), String>;

    /// Idempotently bring on-disk APQ link records to the current schema.
    fn migrate_apq_info(&mut self) -> Result<(), String>;

    /// Idempotently bring the (conversation_id → MLS group id) mapping
    /// table to the current schema.
    fn migrate_conversation_mapping(&mut self) -> Result<(), String>;

    /// Idempotently bring persisted PSK material to the current schema.
    fn migrate_psk_material(&mut self) -> Result<(), String>;

    /// Idempotently bring FULL/PARTIAL commit counters to the current
    /// schema.
    fn migrate_commit_counters(&mut self) -> Result<(), String>;

    /// Idempotently bring `ConversationSecurityState` snapshots to the
    /// current schema.
    fn migrate_anti_downgrade_state(&mut self) -> Result<(), String>;

    /// Returns `true` if the on-disk MLS group state is in the current
    /// schema (post-condition of [`MigrationStep::MigrateGroupState`]).
    fn group_state_present(&self) -> bool;
    /// Post-condition validator for [`MigrationStep::MigrateApqInfo`].
    fn apq_info_present(&self) -> bool;
    /// Post-condition validator for [`MigrationStep::MigrateConversationMapping`].
    fn conversation_mapping_present(&self) -> bool;
    /// Post-condition validator for [`MigrationStep::MigratePskMaterial`].
    fn psk_material_present(&self) -> bool;
    /// Post-condition validator for [`MigrationStep::MigrateCommitCounters`].
    fn commit_counters_present(&self) -> bool;
    /// Post-condition validator for [`MigrationStep::MigrateAntiDowngradeState`].
    fn anti_downgrade_state_present(&self) -> bool;
}

/// Driver that walks every [`MigrationStep`] over a [`MigrationStorage`].
///
/// The driver itself holds no state — every persisted detail lives in the
/// underlying storage so a fresh `StorageMigrator` instance constructed
/// after a crash will resume cleanly.
pub struct StorageMigrator<'a, S: MigrationStorage + ?Sized> {
    store: &'a mut S,
}

impl<'a, S: MigrationStorage + ?Sized> StorageMigrator<'a, S> {
    /// Construct a new migrator borrowing `store` mutably.
    pub fn new(store: &'a mut S) -> Self {
        Self { store }
    }

    /// Run the migration through to [`StorageMigrationState::Complete`].
    ///
    /// Behaviour:
    ///
    /// - `NotStarted`: persist `InProgress(MigrationStep::ALL[0])`, then
    ///   run every step in order.
    /// - `InProgress(step)`: resume from `step` — earlier steps are not
    ///   re-run (their post-conditions are assumed to hold; the caller
    ///   can use [`Self::validate_post_migration`] to double-check).
    /// - `Complete`: no-op, returns `Ok(())`.
    /// - `Failed(reason)`: returns
    ///   [`MigrationError::PreviouslyFailed`].
    pub fn run_migration(&mut self) -> Result<(), MigrationError> {
        let mut current = self.store.read_state();
        if let StorageMigrationState::Failed(reason) = &current {
            return Err(MigrationError::PreviouslyFailed {
                reason: reason.clone(),
            });
        }
        if matches!(current, StorageMigrationState::Complete) {
            return Ok(());
        }
        if matches!(current, StorageMigrationState::NotStarted) {
            current = StorageMigrationState::InProgress(MigrationStep::ALL[0]);
            self.persist(&current)?;
        }

        let StorageMigrationState::InProgress(mut next) = current else {
            // We just normalised every other variant above.
            unreachable!("non-InProgress state should have short-circuited");
        };

        loop {
            // Run the step. Each `migrate_*` is idempotent.
            if let Err(reason) = self.run_step(next) {
                let failed = StorageMigrationState::Failed(reason.clone());
                self.persist(&failed)?;
                return Err(MigrationError::StepFailed { step: next, reason });
            }

            match next.next() {
                Some(after) => {
                    next = after;
                    self.persist(&StorageMigrationState::InProgress(next))?;
                }
                None => {
                    self.persist(&StorageMigrationState::Complete)?;
                    return Ok(());
                }
            }
        }
    }

    /// Validate that the migration is `Complete` *and* every per-step
    /// post-condition holds. Returns
    /// [`MigrationValidationError::NotComplete`] if the migration is not
    /// finished and [`MigrationValidationError::InvariantBroken`] if any
    /// per-step post-condition is missing.
    pub fn validate_post_migration(&self) -> Result<(), MigrationValidationError> {
        let state = self.store.read_state();
        if !matches!(state, StorageMigrationState::Complete) {
            return Err(MigrationValidationError::NotComplete { state });
        }
        for step in MigrationStep::ALL {
            if !self.invariant_holds(*step) {
                return Err(MigrationValidationError::InvariantBroken { step: *step });
            }
        }
        Ok(())
    }

    fn run_step(&mut self, step: MigrationStep) -> Result<(), String> {
        match step {
            MigrationStep::MigrateGroupState => self.store.migrate_group_state(),
            MigrationStep::MigrateApqInfo => self.store.migrate_apq_info(),
            MigrationStep::MigrateConversationMapping => self.store.migrate_conversation_mapping(),
            MigrationStep::MigratePskMaterial => self.store.migrate_psk_material(),
            MigrationStep::MigrateCommitCounters => self.store.migrate_commit_counters(),
            MigrationStep::MigrateAntiDowngradeState => self.store.migrate_anti_downgrade_state(),
        }
    }

    fn invariant_holds(&self, step: MigrationStep) -> bool {
        match step {
            MigrationStep::MigrateGroupState => self.store.group_state_present(),
            MigrationStep::MigrateApqInfo => self.store.apq_info_present(),
            MigrationStep::MigrateConversationMapping => self.store.conversation_mapping_present(),
            MigrationStep::MigratePskMaterial => self.store.psk_material_present(),
            MigrationStep::MigrateCommitCounters => self.store.commit_counters_present(),
            MigrationStep::MigrateAntiDowngradeState => self.store.anti_downgrade_state_present(),
        }
    }

    fn persist(&mut self, state: &StorageMigrationState) -> Result<(), MigrationError> {
        self.store
            .persist_state(state)
            .map_err(|reason| MigrationError::PersistenceFailed { reason })
    }
}

/// Bridge implementation that wires
/// [`openmls_sqlite_storage::SqliteMigrationStorage`] into the
/// [`MigrationStorage`] trait.
///
/// Only available when the `sqlite-provider` feature is enabled. The
/// SQL itself lives in the `openmls_sqlite_storage` crate (so it can be
/// used standalone); this module just glues the rusqlite-typed methods
/// onto the trait surface that the [`StorageMigrator`] driver expects.
#[cfg(feature = "sqlite-provider")]
mod sqlite_bridge {
    use std::borrow::Borrow;

    use openmls_sqlite_storage::{
        Connection, MigrationStateRow, MigrationStepRow, SqliteMigrationStorage,
    };

    use super::{MigrationStep, MigrationStorage, StorageMigrationState};

    impl From<MigrationStep> for MigrationStepRow {
        fn from(step: MigrationStep) -> Self {
            match step {
                MigrationStep::MigrateGroupState => MigrationStepRow::MigrateGroupState,
                MigrationStep::MigrateApqInfo => MigrationStepRow::MigrateApqInfo,
                MigrationStep::MigrateConversationMapping => {
                    MigrationStepRow::MigrateConversationMapping
                }
                MigrationStep::MigratePskMaterial => MigrationStepRow::MigratePskMaterial,
                MigrationStep::MigrateCommitCounters => MigrationStepRow::MigrateCommitCounters,
                MigrationStep::MigrateAntiDowngradeState => {
                    MigrationStepRow::MigrateAntiDowngradeState
                }
            }
        }
    }

    impl From<MigrationStepRow> for MigrationStep {
        fn from(step: MigrationStepRow) -> Self {
            match step {
                MigrationStepRow::MigrateGroupState => MigrationStep::MigrateGroupState,
                MigrationStepRow::MigrateApqInfo => MigrationStep::MigrateApqInfo,
                MigrationStepRow::MigrateConversationMapping => {
                    MigrationStep::MigrateConversationMapping
                }
                MigrationStepRow::MigratePskMaterial => MigrationStep::MigratePskMaterial,
                MigrationStepRow::MigrateCommitCounters => MigrationStep::MigrateCommitCounters,
                MigrationStepRow::MigrateAntiDowngradeState => {
                    MigrationStep::MigrateAntiDowngradeState
                }
            }
        }
    }

    impl From<MigrationStateRow> for StorageMigrationState {
        fn from(state: MigrationStateRow) -> Self {
            match state {
                MigrationStateRow::NotStarted => StorageMigrationState::NotStarted,
                MigrationStateRow::InProgress(step) => {
                    StorageMigrationState::InProgress(step.into())
                }
                MigrationStateRow::Complete => StorageMigrationState::Complete,
                MigrationStateRow::Failed(reason) => StorageMigrationState::Failed(reason),
            }
        }
    }

    impl From<&StorageMigrationState> for MigrationStateRow {
        fn from(state: &StorageMigrationState) -> Self {
            match state {
                StorageMigrationState::NotStarted => MigrationStateRow::NotStarted,
                StorageMigrationState::InProgress(step) => {
                    MigrationStateRow::InProgress((*step).into())
                }
                StorageMigrationState::Complete => MigrationStateRow::Complete,
                StorageMigrationState::Failed(reason) => MigrationStateRow::Failed(reason.clone()),
            }
        }
    }

    impl<C: Borrow<Connection>> MigrationStorage for SqliteMigrationStorage<C> {
        fn read_state(&self) -> StorageMigrationState {
            SqliteMigrationStorage::read_state(self)
                .map(StorageMigrationState::from)
                .unwrap_or_else(|_| StorageMigrationState::NotStarted)
        }

        fn persist_state(&mut self, state: &StorageMigrationState) -> Result<(), String> {
            SqliteMigrationStorage::persist_state(self, &MigrationStateRow::from(state))
                .map_err(|e| e.to_string())
        }

        fn migrate_group_state(&mut self) -> Result<(), String> {
            SqliteMigrationStorage::migrate_group_state(self).map_err(|e| e.to_string())
        }
        fn migrate_apq_info(&mut self) -> Result<(), String> {
            SqliteMigrationStorage::migrate_apq_info(self).map_err(|e| e.to_string())
        }
        fn migrate_conversation_mapping(&mut self) -> Result<(), String> {
            SqliteMigrationStorage::migrate_conversation_mapping(self).map_err(|e| e.to_string())
        }
        fn migrate_psk_material(&mut self) -> Result<(), String> {
            SqliteMigrationStorage::migrate_psk_material(self).map_err(|e| e.to_string())
        }
        fn migrate_commit_counters(&mut self) -> Result<(), String> {
            SqliteMigrationStorage::migrate_commit_counters(self).map_err(|e| e.to_string())
        }
        fn migrate_anti_downgrade_state(&mut self) -> Result<(), String> {
            SqliteMigrationStorage::migrate_anti_downgrade_state(self).map_err(|e| e.to_string())
        }

        fn group_state_present(&self) -> bool {
            SqliteMigrationStorage::group_state_present(self)
        }
        fn apq_info_present(&self) -> bool {
            SqliteMigrationStorage::apq_info_present(self)
        }
        fn conversation_mapping_present(&self) -> bool {
            SqliteMigrationStorage::conversation_mapping_present(self)
        }
        fn psk_material_present(&self) -> bool {
            SqliteMigrationStorage::psk_material_present(self)
        }
        fn commit_counters_present(&self) -> bool {
            SqliteMigrationStorage::commit_counters_present(self)
        }
        fn anti_downgrade_state_present(&self) -> bool {
            SqliteMigrationStorage::anti_downgrade_state_present(self)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::group::storage_migration::StorageMigrator;

        fn fresh_store() -> SqliteMigrationStorage<Connection> {
            let conn = Connection::open_in_memory().expect("open in-memory db");
            SqliteMigrationStorage::new(conn).expect("ensure tables")
        }

        #[test]
        fn sqlite_bridge_drives_full_migration() {
            let mut store = fresh_store();
            let mut migrator = StorageMigrator::new(&mut store);
            migrator
                .run_migration()
                .expect("sqlite-backed migration must succeed");
            migrator
                .validate_post_migration()
                .expect("post-migration validation must pass");
        }

        #[test]
        fn sqlite_bridge_resumes_from_in_progress() {
            let mut store = fresh_store();
            // Pretend a previous run already completed every step
            // before MigratePskMaterial — their on-disk schema would
            // be in place after a crash mid-migration.
            store.migrate_group_state().unwrap();
            store.migrate_apq_info().unwrap();
            store.migrate_conversation_mapping().unwrap();
            // Simulate a crash midway through the plan.
            MigrationStorage::persist_state(
                &mut store,
                &StorageMigrationState::InProgress(MigrationStep::MigratePskMaterial),
            )
            .expect("persist InProgress");
            // Driver should resume from that step and finish.
            let mut migrator = StorageMigrator::new(&mut store);
            migrator.run_migration().expect("resume must succeed");
            migrator
                .validate_post_migration()
                .expect("post-migration validation must pass");
        }

        #[test]
        fn sqlite_bridge_idempotent_double_run() {
            let mut store = fresh_store();
            StorageMigrator::new(&mut store)
                .run_migration()
                .expect("first run");
            StorageMigrator::new(&mut store)
                .run_migration()
                .expect("second run must be a no-op");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test double: an in-memory [`MigrationStorage`] that records which
    /// `migrate_*` methods were called and in what order. Each step
    /// flips a per-step "present" bit so `*_present` returns `true` once
    /// the step has run at least once — i.e. the per-step idempotency
    /// is real even though the test does no actual schema work.
    #[derive(Debug, Default, Clone)]
    struct InMemoryStore {
        state: Option<StorageMigrationState>,
        calls: Vec<MigrationStep>,
        present: [bool; 6],
        fail_at: Option<MigrationStep>,
        skip_persist: bool,
    }

    impl InMemoryStore {
        fn new() -> Self {
            Self::default()
        }

        fn with_state(mut self, state: StorageMigrationState) -> Self {
            self.state = Some(state);
            self
        }

        fn with_fail_at(mut self, step: MigrationStep) -> Self {
            self.fail_at = Some(step);
            self
        }

        fn mark(&mut self, step: MigrationStep) -> Result<(), String> {
            if self.fail_at == Some(step) {
                return Err(format!("simulated failure at {step:?}"));
            }
            self.calls.push(step);
            self.present[step.index()] = true;
            Ok(())
        }
    }

    impl MigrationStorage for InMemoryStore {
        fn read_state(&self) -> StorageMigrationState {
            self.state
                .clone()
                .unwrap_or(StorageMigrationState::NotStarted)
        }
        fn persist_state(&mut self, state: &StorageMigrationState) -> Result<(), String> {
            if self.skip_persist {
                return Err("simulated persistence failure".into());
            }
            self.state = Some(state.clone());
            Ok(())
        }
        fn migrate_group_state(&mut self) -> Result<(), String> {
            self.mark(MigrationStep::MigrateGroupState)
        }
        fn migrate_apq_info(&mut self) -> Result<(), String> {
            self.mark(MigrationStep::MigrateApqInfo)
        }
        fn migrate_conversation_mapping(&mut self) -> Result<(), String> {
            self.mark(MigrationStep::MigrateConversationMapping)
        }
        fn migrate_psk_material(&mut self) -> Result<(), String> {
            self.mark(MigrationStep::MigratePskMaterial)
        }
        fn migrate_commit_counters(&mut self) -> Result<(), String> {
            self.mark(MigrationStep::MigrateCommitCounters)
        }
        fn migrate_anti_downgrade_state(&mut self) -> Result<(), String> {
            self.mark(MigrationStep::MigrateAntiDowngradeState)
        }
        fn group_state_present(&self) -> bool {
            self.present[MigrationStep::MigrateGroupState.index()]
        }
        fn apq_info_present(&self) -> bool {
            self.present[MigrationStep::MigrateApqInfo.index()]
        }
        fn conversation_mapping_present(&self) -> bool {
            self.present[MigrationStep::MigrateConversationMapping.index()]
        }
        fn psk_material_present(&self) -> bool {
            self.present[MigrationStep::MigratePskMaterial.index()]
        }
        fn commit_counters_present(&self) -> bool {
            self.present[MigrationStep::MigrateCommitCounters.index()]
        }
        fn anti_downgrade_state_present(&self) -> bool {
            self.present[MigrationStep::MigrateAntiDowngradeState.index()]
        }
    }

    /// Fresh `NotStarted` store: every step runs in order; final state
    /// is `Complete`; validation passes.
    #[test]
    fn fresh_migration_runs_every_step_in_order_and_completes() {
        let mut store = InMemoryStore::new();
        let mut migrator = StorageMigrator::new(&mut store);
        migrator
            .run_migration()
            .expect("fresh migration must succeed");
        assert_eq!(store.read_state(), StorageMigrationState::Complete);
        assert_eq!(store.calls, MigrationStep::ALL.to_vec());

        let migrator = StorageMigrator::new(&mut store);
        migrator
            .validate_post_migration()
            .expect("post-migration validation must pass");
    }

    /// Re-running a `Complete` migration is a no-op: no `migrate_*`
    /// method fires, the state stays `Complete`.
    #[test]
    fn complete_migration_is_idempotent_on_rerun() {
        let mut store = InMemoryStore::new();
        StorageMigrator::new(&mut store)
            .run_migration()
            .expect("first run");
        let calls_after_first = store.calls.clone();

        StorageMigrator::new(&mut store)
            .run_migration()
            .expect("second run must be a no-op");

        assert_eq!(store.calls, calls_after_first, "no extra calls on re-run");
        assert_eq!(store.read_state(), StorageMigrationState::Complete);
    }

    /// Resume after crash at the first step: the marker says
    /// `InProgress(MigrateGroupState)`. The migrator runs every step
    /// from there.
    #[test]
    fn resume_after_crash_at_group_state_runs_every_remaining_step() {
        resume_after_crash_test(MigrationStep::MigrateGroupState);
    }

    /// Resume after crash at MigrateApqInfo: only the remaining steps
    /// (MigrateApqInfo onwards) run on this attempt.
    #[test]
    fn resume_after_crash_at_apq_info_runs_remaining_steps() {
        resume_after_crash_test(MigrationStep::MigrateApqInfo);
    }

    /// Resume after crash at MigrateConversationMapping.
    #[test]
    fn resume_after_crash_at_conversation_mapping() {
        resume_after_crash_test(MigrationStep::MigrateConversationMapping);
    }

    /// Resume after crash at MigratePskMaterial.
    #[test]
    fn resume_after_crash_at_psk_material() {
        resume_after_crash_test(MigrationStep::MigratePskMaterial);
    }

    /// Resume after crash at MigrateCommitCounters.
    #[test]
    fn resume_after_crash_at_commit_counters() {
        resume_after_crash_test(MigrationStep::MigrateCommitCounters);
    }

    /// Resume after crash at the very last step.
    #[test]
    fn resume_after_crash_at_anti_downgrade_state() {
        resume_after_crash_test(MigrationStep::MigrateAntiDowngradeState);
    }

    fn resume_after_crash_test(resume_at: MigrationStep) {
        let mut store =
            InMemoryStore::new().with_state(StorageMigrationState::InProgress(resume_at));
        // Pretend earlier steps already ran (their on-disk schema would
        // be in the new shape after a crash mid-migration).
        for step in MigrationStep::ALL.iter().take_while(|s| **s != resume_at) {
            store.present[step.index()] = true;
        }

        StorageMigrator::new(&mut store)
            .run_migration()
            .expect("resume must succeed");

        let expected_calls: Vec<_> = MigrationStep::ALL
            .iter()
            .copied()
            .skip_while(|s| *s != resume_at)
            .collect();
        assert_eq!(
            store.calls, expected_calls,
            "expected to resume from {resume_at:?} and run only the remaining steps",
        );
        assert_eq!(store.read_state(), StorageMigrationState::Complete);
        StorageMigrator::new(&mut store)
            .validate_post_migration()
            .expect("post-migration validation must pass after resume");
    }

    /// A failing step must persist `Failed(reason)` and must not silently
    /// retry on the next call.
    #[test]
    fn step_failure_is_persisted_and_blocks_retry() {
        let mut store = InMemoryStore::new().with_fail_at(MigrationStep::MigrateApqInfo);
        let err = StorageMigrator::new(&mut store)
            .run_migration()
            .expect_err("MigrateApqInfo must propagate failure");
        assert!(matches!(
            err,
            MigrationError::StepFailed {
                step: MigrationStep::MigrateApqInfo,
                ..
            }
        ));
        assert!(matches!(
            store.read_state(),
            StorageMigrationState::Failed(_)
        ));

        // Fix the underlying issue and re-run: PreviouslyFailed.
        store.fail_at = None;
        let err = StorageMigrator::new(&mut store)
            .run_migration()
            .expect_err("Failed state must block retry until cleared");
        assert!(matches!(err, MigrationError::PreviouslyFailed { .. }));
    }

    /// `validate_post_migration` returns `NotComplete` while the
    /// migrator is mid-flight, and `Ok(())` once every post-condition
    /// holds.
    #[test]
    fn validation_distinguishes_in_progress_from_complete() {
        let mut store = InMemoryStore::new();
        let migrator = StorageMigrator::new(&mut store);
        let err = migrator
            .validate_post_migration()
            .expect_err("not yet started must fail validation");
        assert!(matches!(err, MigrationValidationError::NotComplete { .. }));

        let mut store = InMemoryStore::new();
        StorageMigrator::new(&mut store).run_migration().unwrap();
        StorageMigrator::new(&mut store)
            .validate_post_migration()
            .expect("Complete must validate");
    }

    /// `validate_post_migration` must catch a broken invariant even when
    /// the persisted marker is `Complete`. This guards against a bug
    /// where a migration step "succeeds" but never actually writes its
    /// target schema.
    #[test]
    fn validation_catches_missing_invariant_after_complete() {
        let mut store = InMemoryStore::new();
        StorageMigrator::new(&mut store).run_migration().unwrap();
        // Simulate a schema-level corruption: clear one of the present
        // bits while the marker is still `Complete`.
        store.present[MigrationStep::MigratePskMaterial.index()] = false;
        let err = StorageMigrator::new(&mut store)
            .validate_post_migration()
            .expect_err("missing invariant must surface");
        assert!(matches!(
            err,
            MigrationValidationError::InvariantBroken {
                step: MigrationStep::MigratePskMaterial
            }
        ));
    }

    /// State persistence round-trip: every variant survives a write +
    /// read.
    #[test]
    fn state_persistence_round_trip_for_every_variant() {
        let mut store = InMemoryStore::new();
        for state in [
            StorageMigrationState::NotStarted,
            StorageMigrationState::InProgress(MigrationStep::MigrateGroupState),
            StorageMigrationState::InProgress(MigrationStep::MigrateAntiDowngradeState),
            StorageMigrationState::Complete,
            StorageMigrationState::Failed("oops".into()),
        ] {
            store.persist_state(&state).expect("persist");
            assert_eq!(store.read_state(), state);
        }
    }
}
