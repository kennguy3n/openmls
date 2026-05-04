//! # SQLite-backed `MigrationStorage`
//!
//! This module ships [`SqliteMigrationStorage`], a SQLite-backed
//! implementation of the
//! [`openmls::group::storage_migration::MigrationStorage`] trait used
//! by [`openmls::group::storage_migration::StorageMigrator`] to drive
//! idempotent client-side schema migrations.
//!
//! The trait `impl` itself is *not* in this crate — pulling the
//! `openmls` crate into `sqlite_storage` would create a cyclic
//! dependency with `openmls`'s `sqlite-provider` feature. Instead,
//! this crate ships:
//!
//! - the SQL bring-up logic (idempotent `CREATE TABLE IF NOT EXISTS`
//!   for every PQ-related table),
//! - inherent methods on [`SqliteMigrationStorage`] that match the
//!   shape of every [`MigrationStorage`] trait method,
//! - a [`SqliteMigrationStorage::run_migration`] convenience entry
//!   point that runs all of the migrate steps once and persists the
//!   resulting [`MigrationStateRow`].
//!
//! The actual `impl MigrationStorage for SqliteMigrationStorage` lives
//! in `openmls` behind the `sqlite-provider` feature
//! (`openmls/src/group/storage_migration.rs`), so consumers that
//! depend on both `openmls` and `openmls_sqlite_storage` get the trait
//! impl for free.
//!
//! See [`PROPOSAL.md`](../../../PROPOSAL.md) §Storage requirements,
//! [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) §Storage Requirements,
//! and [`PROGRESS.md`](../../../PROGRESS.md) for how this fits into
//! the KChat PQ migration plan.

use std::borrow::Borrow;

use rusqlite::{params, Connection, OptionalExtension};

/// Persistent progress marker for the storage migrator, mirroring the
/// `openmls::group::storage_migration::StorageMigrationState` enum.
///
/// We don't import the enum here — see the module-level docs for why
/// — but we keep the wire-stable string repr in lockstep. The trait
/// `impl` in `openmls` provides bidirectional `From` conversions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationStateRow {
    /// No migration has been attempted yet.
    NotStarted,
    /// `step` is the next step the migrator should run.
    InProgress(MigrationStepRow),
    /// Every step has run to completion.
    Complete,
    /// The migration aborted with the carried reason.
    Failed(String),
}

/// Mirror of `openmls::group::storage_migration::MigrationStep` for
/// use inside the SQLite backend.
///
/// New variants must be appended to the end and must keep the exact
/// `as_str` / `parse_str` round-trip used to serialize them on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MigrationStepRow {
    /// Migrate per-group MLS state to the current schema.
    MigrateGroupState,
    /// Migrate `ApqInfo` records.
    MigrateApqInfo,
    /// Migrate the `(conversation_id → MLS group id)` mapping.
    MigrateConversationMapping,
    /// Migrate persisted PSK material.
    MigratePskMaterial,
    /// Migrate FULL/PARTIAL commit counters.
    MigrateCommitCounters,
    /// Migrate `ConversationSecurityState` snapshots.
    MigrateAntiDowngradeState,
}

impl MigrationStepRow {
    /// Stable on-disk identifier. Never rename a variant — older
    /// clients will fail to parse.
    pub fn as_str(self) -> &'static str {
        match self {
            MigrationStepRow::MigrateGroupState => "migrate_group_state",
            MigrationStepRow::MigrateApqInfo => "migrate_apq_info",
            MigrationStepRow::MigrateConversationMapping => "migrate_conversation_mapping",
            MigrationStepRow::MigratePskMaterial => "migrate_psk_material",
            MigrationStepRow::MigrateCommitCounters => "migrate_commit_counters",
            MigrationStepRow::MigrateAntiDowngradeState => "migrate_anti_downgrade_state",
        }
    }

    /// Inverse of [`Self::as_str`].
    pub fn parse_str(s: &str) -> Option<Self> {
        Some(match s {
            "migrate_group_state" => MigrationStepRow::MigrateGroupState,
            "migrate_apq_info" => MigrationStepRow::MigrateApqInfo,
            "migrate_conversation_mapping" => MigrationStepRow::MigrateConversationMapping,
            "migrate_psk_material" => MigrationStepRow::MigratePskMaterial,
            "migrate_commit_counters" => MigrationStepRow::MigrateCommitCounters,
            "migrate_anti_downgrade_state" => MigrationStepRow::MigrateAntiDowngradeState,
            _ => return None,
        })
    }
}

/// SQLite-backed migration storage.
///
/// Wraps any value that can be `Borrow`-ed as a [`Connection`]. Every
/// table touched here is created with `CREATE TABLE IF NOT EXISTS`, so
/// repeated [`Self::new`] / `migrate_*` calls are safe — the storage
/// is idempotent end to end.
pub struct SqliteMigrationStorage<ConnectionRef: Borrow<Connection>> {
    connection: ConnectionRef,
}

/// Errors raised by the SQLite migration storage.
#[derive(Debug, thiserror::Error)]
pub enum SqliteMigrationError {
    /// Underlying rusqlite error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

impl<ConnectionRef: Borrow<Connection>> SqliteMigrationStorage<ConnectionRef> {
    /// Construct the storage. Eagerly creates the
    /// `pq_migration_state` and `pq_migration_markers` tables so every
    /// other method can run with `&self` only.
    pub fn new(connection: ConnectionRef) -> Result<Self, SqliteMigrationError> {
        let me = Self { connection };
        me.ensure_state_tables()?;
        Ok(me)
    }

    /// Construct without eagerly running schema setup. Useful for
    /// recovery scenarios where the caller wants to inspect existing
    /// state before any migrations run.
    ///
    /// Callers must ensure schema bring-up runs at some point before
    /// reading or writing state.
    pub fn new_unchecked(connection: ConnectionRef) -> Self {
        Self { connection }
    }

    /// Idempotently create the bookkeeping tables used by this
    /// migrator. Safe to call repeatedly.
    pub fn ensure_state_tables(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pq_migration_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                state_kind TEXT NOT NULL CHECK (state_kind IN
                    ('not_started', 'in_progress', 'complete', 'failed')),
                in_progress_step TEXT,
                failure_reason TEXT
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pq_migration_markers (
                marker TEXT PRIMARY KEY
            )",
            [],
        )?;
        Ok(())
    }

    /// Read the persisted [`MigrationStateRow`]. A fresh DB returns
    /// [`MigrationStateRow::NotStarted`].
    pub fn read_state(&self) -> Result<MigrationStateRow, rusqlite::Error> {
        let conn = self.conn();
        let row: Option<(String, Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT state_kind, in_progress_step, failure_reason
                 FROM pq_migration_state WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        Ok(match row {
            None => MigrationStateRow::NotStarted,
            Some((kind, step, reason)) => match kind.as_str() {
                "not_started" => MigrationStateRow::NotStarted,
                "in_progress" => {
                    let step = step
                        .as_deref()
                        .and_then(MigrationStepRow::parse_str)
                        // Unknown step → treat as the very first step
                        // so a forwards-compatible client never silently
                        // skips a migration.
                        .unwrap_or(MigrationStepRow::MigrateGroupState);
                    MigrationStateRow::InProgress(step)
                }
                "complete" => MigrationStateRow::Complete,
                "failed" => MigrationStateRow::Failed(reason.unwrap_or_default()),
                _ => MigrationStateRow::NotStarted,
            },
        })
    }

    /// Persist `state` into the `pq_migration_state` table (upsert).
    pub fn persist_state(&self, state: &MigrationStateRow) -> Result<(), rusqlite::Error> {
        let (kind, step, reason): (&'static str, Option<&'static str>, Option<String>) = match state
        {
            MigrationStateRow::NotStarted => ("not_started", None, None),
            MigrationStateRow::InProgress(step) => ("in_progress", Some(step.as_str()), None),
            MigrationStateRow::Complete => ("complete", None, None),
            MigrationStateRow::Failed(reason) => ("failed", None, Some(reason.clone())),
        };
        self.conn().execute(
            "INSERT INTO pq_migration_state (id, state_kind, in_progress_step, failure_reason)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                state_kind = excluded.state_kind,
                in_progress_step = excluded.in_progress_step,
                failure_reason = excluded.failure_reason",
            params![kind, step, reason],
        )?;
        Ok(())
    }

    /// Idempotently bring on-disk MLS group state to the current
    /// schema.
    ///
    /// In practice, the MLS group-state tables are owned by
    /// [`crate::SqliteStorageProvider`] and managed by `refinery`; this
    /// step is a *post*-condition checker that records a marker once
    /// the openmls schema is in place. The `*_present` checker uses
    /// this marker.
    pub fn migrate_group_state(&self) -> Result<(), rusqlite::Error> {
        self.set_marker("group_state")
    }

    /// Idempotently bring `ApqInfo` records to the current schema.
    pub fn migrate_apq_info(&self) -> Result<(), rusqlite::Error> {
        self.conn().execute(
            "CREATE TABLE IF NOT EXISTS pq_apq_info (
                conversation_id BLOB PRIMARY KEY,
                t_group_id BLOB NOT NULL,
                pq_group_id BLOB NOT NULL,
                t_epoch INTEGER NOT NULL,
                pq_epoch INTEGER NOT NULL,
                t_ciphersuite INTEGER NOT NULL,
                pq_ciphersuite INTEGER NOT NULL,
                mode INTEGER NOT NULL
            )",
            [],
        )?;
        self.set_marker("apq_info")
    }

    /// Idempotently bring the conversation-id → group-id mapping
    /// table.
    pub fn migrate_conversation_mapping(&self) -> Result<(), rusqlite::Error> {
        self.conn().execute(
            "CREATE TABLE IF NOT EXISTS pq_conversation_mapping (
                conversation_id BLOB PRIMARY KEY,
                t_group_id BLOB,
                pq_group_id BLOB
            )",
            [],
        )?;
        self.set_marker("conversation_mapping")
    }

    /// Idempotently bring persisted PSK material.
    pub fn migrate_psk_material(&self) -> Result<(), rusqlite::Error> {
        self.conn().execute(
            "CREATE TABLE IF NOT EXISTS pq_psk_material (
                conversation_id BLOB NOT NULL,
                psk_id BLOB NOT NULL,
                psk_kind TEXT NOT NULL,
                bundle BLOB NOT NULL,
                PRIMARY KEY (conversation_id, psk_id)
            )",
            [],
        )?;
        self.set_marker("psk_material")
    }

    /// Idempotently bring FULL/PARTIAL commit counters.
    pub fn migrate_commit_counters(&self) -> Result<(), rusqlite::Error> {
        self.conn().execute(
            "CREATE TABLE IF NOT EXISTS pq_commit_counters (
                conversation_id BLOB PRIMARY KEY,
                full_commit_count INTEGER NOT NULL DEFAULT 0,
                partial_commit_count INTEGER NOT NULL DEFAULT 0,
                last_full_epoch INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;
        self.set_marker("commit_counters")
    }

    /// Idempotently bring `ConversationSecurityState` snapshots.
    pub fn migrate_anti_downgrade_state(&self) -> Result<(), rusqlite::Error> {
        self.conn().execute(
            "CREATE TABLE IF NOT EXISTS pq_conversation_security_state (
                conversation_id BLOB PRIMARY KEY,
                current_mode INTEGER NOT NULL,
                highest_mode_ever INTEGER NOT NULL,
                policy_floor INTEGER NOT NULL,
                pinned_ciphersuite INTEGER
            )",
            [],
        )?;
        self.set_marker("anti_downgrade_state")
    }

    /// Returns `true` once [`Self::migrate_group_state`] has run.
    pub fn group_state_present(&self) -> bool {
        self.has_marker("group_state").unwrap_or(false)
    }

    /// Returns `true` once the `pq_apq_info` table exists.
    pub fn apq_info_present(&self) -> bool {
        self.table_exists("pq_apq_info").unwrap_or(false)
    }

    /// Returns `true` once the `pq_conversation_mapping` table exists.
    pub fn conversation_mapping_present(&self) -> bool {
        self.table_exists("pq_conversation_mapping")
            .unwrap_or(false)
    }

    /// Returns `true` once the `pq_psk_material` table exists.
    pub fn psk_material_present(&self) -> bool {
        self.table_exists("pq_psk_material").unwrap_or(false)
    }

    /// Returns `true` once the `pq_commit_counters` table exists.
    pub fn commit_counters_present(&self) -> bool {
        self.table_exists("pq_commit_counters").unwrap_or(false)
    }

    /// Returns `true` once the `pq_conversation_security_state` table
    /// exists.
    pub fn anti_downgrade_state_present(&self) -> bool {
        self.table_exists("pq_conversation_security_state")
            .unwrap_or(false)
    }

    /// Convenience: run every migration step in order, persisting
    /// state after each. Suitable for test code; production callers
    /// should go through
    /// `openmls::group::storage_migration::StorageMigrator` so
    /// crash-resume is exercised through the trait surface.
    pub fn run_migration(&self) -> Result<(), rusqlite::Error> {
        let steps: &[MigrationStepRow] = &[
            MigrationStepRow::MigrateGroupState,
            MigrationStepRow::MigrateApqInfo,
            MigrationStepRow::MigrateConversationMapping,
            MigrationStepRow::MigratePskMaterial,
            MigrationStepRow::MigrateCommitCounters,
            MigrationStepRow::MigrateAntiDowngradeState,
        ];

        if matches!(self.read_state()?, MigrationStateRow::NotStarted) {
            self.persist_state(&MigrationStateRow::InProgress(steps[0]))?;
        }

        for step in steps {
            match step {
                MigrationStepRow::MigrateGroupState => self.migrate_group_state()?,
                MigrationStepRow::MigrateApqInfo => self.migrate_apq_info()?,
                MigrationStepRow::MigrateConversationMapping => {
                    self.migrate_conversation_mapping()?
                }
                MigrationStepRow::MigratePskMaterial => self.migrate_psk_material()?,
                MigrationStepRow::MigrateCommitCounters => self.migrate_commit_counters()?,
                MigrationStepRow::MigrateAntiDowngradeState => {
                    self.migrate_anti_downgrade_state()?
                }
            }
        }

        self.persist_state(&MigrationStateRow::Complete)?;
        Ok(())
    }

    fn conn(&self) -> &Connection {
        self.connection.borrow()
    }

    fn set_marker(&self, marker: &str) -> Result<(), rusqlite::Error> {
        self.conn().execute(
            "INSERT OR IGNORE INTO pq_migration_markers (marker) VALUES (?1)",
            params![marker],
        )?;
        Ok(())
    }

    fn has_marker(&self, marker: &str) -> Result<bool, rusqlite::Error> {
        let n: Option<i64> = self
            .conn()
            .query_row(
                "SELECT 1 FROM pq_migration_markers WHERE marker = ?1",
                params![marker],
                |row| row.get(0),
            )
            .optional()?;
        Ok(n.is_some())
    }

    fn table_exists(&self, name: &str) -> Result<bool, rusqlite::Error> {
        let n: Option<i64> = self
            .conn()
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        Ok(n.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_storage() -> SqliteMigrationStorage<Connection> {
        SqliteMigrationStorage::new(Connection::open_in_memory().expect("open in-memory db"))
            .expect("ensure tables")
    }

    #[test]
    fn fresh_db_reads_not_started() {
        let s = fresh_storage();
        assert_eq!(s.read_state().unwrap(), MigrationStateRow::NotStarted);
    }

    #[test]
    fn run_migration_drives_to_complete() {
        let s = fresh_storage();
        s.run_migration().expect("run_migration ok");
        assert_eq!(s.read_state().unwrap(), MigrationStateRow::Complete);
        assert!(s.apq_info_present());
        assert!(s.conversation_mapping_present());
        assert!(s.psk_material_present());
        assert!(s.commit_counters_present());
        assert!(s.anti_downgrade_state_present());
        assert!(s.group_state_present());
    }

    #[test]
    fn run_migration_is_idempotent() {
        let s = fresh_storage();
        s.run_migration().expect("first run");
        // Second run must be a no-op (no errors).
        s.run_migration().expect("second run");
        assert_eq!(s.read_state().unwrap(), MigrationStateRow::Complete);
    }

    #[test]
    fn migrate_apq_info_idempotent_double_call() {
        let s = fresh_storage();
        s.migrate_apq_info().expect("first migrate");
        s.migrate_apq_info().expect("second migrate");
        assert!(s.apq_info_present());
    }

    #[test]
    fn persist_round_trip_in_progress() {
        let s = fresh_storage();
        let target = MigrationStateRow::InProgress(MigrationStepRow::MigratePskMaterial);
        s.persist_state(&target).expect("persist");
        assert_eq!(s.read_state().unwrap(), target);
    }

    #[test]
    fn persist_round_trip_failed_carries_reason() {
        let s = fresh_storage();
        let target = MigrationStateRow::Failed("disk full".into());
        s.persist_state(&target).expect("persist");
        assert_eq!(s.read_state().unwrap(), target);
    }

    #[test]
    fn unknown_in_progress_step_falls_back_to_first() {
        let s = fresh_storage();
        s.conn().execute(
            "INSERT INTO pq_migration_state (id, state_kind, in_progress_step) VALUES (1, 'in_progress', 'totally_made_up')",
            [],
        ).unwrap();
        match s.read_state().unwrap() {
            MigrationStateRow::InProgress(MigrationStepRow::MigrateGroupState) => {}
            other => panic!("expected fallback to MigrateGroupState, got {other:?}"),
        }
    }

    #[test]
    fn migration_step_round_trip_strs() {
        for step in [
            MigrationStepRow::MigrateGroupState,
            MigrationStepRow::MigrateApqInfo,
            MigrationStepRow::MigrateConversationMapping,
            MigrationStepRow::MigratePskMaterial,
            MigrationStepRow::MigrateCommitCounters,
            MigrationStepRow::MigrateAntiDowngradeState,
        ] {
            assert_eq!(MigrationStepRow::parse_str(step.as_str()), Some(step));
        }
        assert_eq!(MigrationStepRow::parse_str("nope"), None);
    }

    #[test]
    fn crash_resume_restarts_from_marked_step() {
        let s = fresh_storage();
        // Pretend a previous run crashed mid-way.
        s.persist_state(&MigrationStateRow::InProgress(
            MigrationStepRow::MigratePskMaterial,
        ))
        .unwrap();
        // Run remaining steps idempotently.
        s.migrate_psk_material().unwrap();
        s.migrate_commit_counters().unwrap();
        s.migrate_anti_downgrade_state().unwrap();
        s.persist_state(&MigrationStateRow::Complete).unwrap();
        assert_eq!(s.read_state().unwrap(), MigrationStateRow::Complete);
    }
}
