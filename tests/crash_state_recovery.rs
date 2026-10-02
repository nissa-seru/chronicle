//! Process-crash recovery: the child exits without running Store::drop.
//! These tests cover process death, not storage-device/power-loss behavior.

use chronicle::{
    BranchId, FieldIndexKind, PayloadEncoding, RecordId, RecordInput, RecordLog, Sequence,
    StateOperation, StateRegistration, StateStrategy, StateUpdateRecord, Store, StoreConfig,
    StoreError, Timestamp, TreeEntry,
};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn config(path: &Path) -> StoreConfig {
    StoreConfig {
        path: path.to_owned(),
        ..Default::default()
    }
}

fn register(store: &Store, id: &str, strategy: StateStrategy) {
    store
        .register_state(StateRegistration {
            id: id.into(),
            strategy,
            initial_value: None,
        })
        .unwrap();
}

fn log_strategy() -> StateStrategy {
    StateStrategy::AppendLog {
        delta_snapshot_every: 2,
        full_snapshot_every: 2,
    }
}

fn append(store: &Store, id: &str, value: Value) {
    store
        .update_state(
            id,
            StateOperation::Append(serde_json::to_vec(&value).unwrap()),
        )
        .unwrap();
}

fn value(store: &Store, id: &str) -> Value {
    store
        .get_state(id)
        .unwrap()
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .unwrap_or(Value::Null)
}

fn observe(store: &Store) -> Value {
    let states: Vec<_> = ["items", "files", "settings"]
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "value": value(store, id),
                "len": store.get_state_len(id).unwrap(),
                "snapshot_needed": format!("{:?}", store.snapshot_needed(id)),
                "compaction": format!("{:?}", store.get_compaction_stats(id)),
            })
        })
        .collect();
    json!({
        "states": states,
        "head": store.current_branch().head.0,
        "records": store.stats().unwrap().record_count,
        "field_matches": store.query_state_index_range("items", "/n", Some(5.0), None, None, None, false),
    })
}

fn crash(path: &Path, scenario: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_writer", "--nocapture"])
        .env("CHRONICLE_CRASH_PATH", path)
        .env("CHRONICLE_CRASH_SCENARIO", scenario)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(73),
        "child did not reach crash point:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn crash_writer() {
    let Some(path) = std::env::var_os("CHRONICLE_CRASH_PATH") else {
        return;
    };
    let path = Path::new(&path);
    let scenario = std::env::var("CHRONICLE_CRASH_SCENARIO").unwrap();
    if scenario == "reopen" {
        let store = Store::open(config(path)).unwrap();
        assert_eq!(store.get_state_len("items").unwrap(), Some(10));
        // Crash again after replay, before the recovered heads are saved.
        std::process::exit(73);
    }
    let store = Store::create(config(path)).unwrap();
    register(&store, "items", log_strategy());

    match scenario.as_str() {
        "registration" => {
            store
                .update_state_strategy(
                    "items",
                    StateStrategy::AppendLog {
                        delta_snapshot_every: 17,
                        full_snapshot_every: 11,
                    },
                )
                .unwrap();
        }
        "fresh" | "tail" | "torn" => {
            store.set_auto_snapshot(false);
            for n in 0..10 {
                append(&store, "items", json!(n));
                if scenario != "fresh" && n == 4 {
                    store.sync().unwrap();
                }
            }
            assert_eq!(store.get_state_len("items").unwrap(), Some(10));
            if scenario == "tail" {
                store
                    .append(RecordInput::raw("message", b"ordinary log tail".to_vec()))
                    .unwrap();
            }
        }
        "mixed" => {
            register(
                &store,
                "files",
                StateStrategy::Tree {
                    delta_snapshot_every: 2,
                    full_snapshot_every: 2,
                },
            );
            register(&store, "settings", StateStrategy::Snapshot);
            append(&store, "items", json!({"n": 0}));
            store
                .register_state_field_index("items", "/n", FieldIndexKind::Number)
                .unwrap();
            store.sync().unwrap();
            for n in 1..15 {
                append(&store, "items", json!({"n": n}));
                store
                    .tree_set(
                        "files",
                        &format!("file-{n}"),
                        &TreeEntry {
                            blob_hash: format!("hash-{n}"),
                            size: n,
                            mode: 0o644,
                        },
                    )
                    .unwrap();
                store
                    .update_state(
                        "settings",
                        StateOperation::Set(serde_json::to_vec(&json!({"n": n})).unwrap()),
                    )
                    .unwrap();
            }
            store
                .update_state(
                    "items",
                    StateOperation::Edit {
                        index: 3,
                        new_value: br#"{"n":99}"#.to_vec(),
                    },
                )
                .unwrap();
            store
                .update_state("items", StateOperation::Redact { start: 1, end: 3 })
                .unwrap();
            store.tree_remove("files", "file-4").unwrap();
            store.append(RecordInput::raw("message", vec![])).unwrap();
            std::fs::write(
                path.join("expected.json"),
                serde_json::to_vec(&observe(&store)).unwrap(),
            )
            .unwrap();
        }
        "delete" => {
            store.set_auto_snapshot(false);
            append(&store, "items", json!(0));
            store.create_branch("gone", None).unwrap();
            store.switch_branch("gone").unwrap();
            for n in 1..5 {
                append(&store, "items", json!(n));
            }
            store.switch_branch("main").unwrap();
            store.delete_branch("gone").unwrap();
            append(&store, "items", json!(9));
        }
        mode => {
            store.set_auto_snapshot(false);
            append(&store, "items", json!(0));
            append(&store, "items", json!(1));
            match mode.split('-').next().unwrap() {
                "branch" => {
                    store.create_branch("feature", None).unwrap();
                }
                "at" => {
                    store
                        .create_branch_at("feature", "main", Sequence(1))
                        .unwrap();
                }
                "empty" => {
                    store.create_empty_branch("feature", None).unwrap();
                }
                other => panic!("unknown scenario {other}"),
            }
            if mode.ends_with("tail") {
                store.switch_branch("feature").unwrap();
                for n in 2..5 {
                    append(&store, "items", json!(n));
                }
            }
        }
    }

    // No destructors: unlike dropping the Store, this cannot flush metadata.
    std::process::exit(73);
}

#[test]
fn registration_and_strategy_change_survive_without_close() {
    let dir = TempDir::new().unwrap();
    crash(dir.path(), "registration");
    let store = Store::open(config(dir.path())).unwrap();
    assert_eq!(store.stats().unwrap().state_slot_count, 1);
    assert!(matches!(
        store.register_state(StateRegistration {
            id: "items".into(),
            strategy: log_strategy(),
            initial_value: None,
        }),
        Err(StoreError::StateExists(_))
    ));
    for n in 0..16 {
        append(&store, "items", json!(n));
    }
    assert_eq!(
        store.stats().unwrap().record_count,
        16,
        "retuned cadence survived"
    );
    append(&store, "items", json!(16));
    assert_eq!(
        store.stats().unwrap().record_count,
        18,
        "delta at retuned threshold"
    );
}

#[test]
fn new_store_and_incremental_tail_replay_without_duplicates() {
    for scenario in ["fresh", "tail"] {
        let dir = TempDir::new().unwrap();
        crash(dir.path(), scenario);
        crash(dir.path(), "reopen");
        for cycle in 0..2 {
            let store = Store::open(config(dir.path())).unwrap();
            assert_eq!(
                value(&store, "items"),
                json!([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
            );
            assert_eq!(store.get_state_len("items").unwrap(), Some(10));
            assert_eq!(
                store.stats().unwrap().record_count,
                if scenario == "tail" { 11 } else { 10 }
            );
            assert!(store.recovery().is_none(), "an intact tail loses no bytes");
            if cycle == 1 {
                store.set_auto_snapshot(false);
                append(&store, "items", json!(10));
                assert_eq!(store.get_state_len("items").unwrap(), Some(11));
                assert_eq!(
                    store.current_branch().head.0,
                    if scenario == "tail" { 12 } else { 11 }
                );
            }
        }
    }
}

#[test]
fn replay_restores_mixed_operations_snapshots_and_field_index() {
    let dir = TempDir::new().unwrap();
    crash(dir.path(), "mixed");
    let expected: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("expected.json")).unwrap()).unwrap();
    for _ in 0..2 {
        let store = Store::open(config(dir.path())).unwrap();
        assert_eq!(observe(&store), expected);
        assert_eq!(value(&store, "items").as_array().unwrap().len(), 13);
        assert_eq!(
            store.get_state_at("items", Sequence(1)).unwrap(),
            Some(br#"[{"n":0}]"#.to_vec())
        );
    }
}

#[test]
fn all_branch_creation_paths_survive_with_inherited_heads_and_tail() {
    for (kind, base) in [
        ("branch", json!([0, 1])),
        ("at", json!([0])),
        ("empty", Value::Null),
    ] {
        for suffix in ["created", "tail"] {
            let dir = TempDir::new().unwrap();
            crash(dir.path(), &format!("{kind}-{suffix}"));
            let store = Store::open(config(dir.path())).unwrap();
            assert_eq!(store.list_branches().len(), 2, "{kind}-{suffix}");
            assert_eq!(
                store.current_branch().name,
                if suffix == "tail" { "feature" } else { "main" }
            );
            store.switch_branch("feature").unwrap();
            let mut expected = base.as_array().cloned().unwrap_or_default();
            if suffix == "tail" {
                expected.extend([json!(2), json!(3), json!(4)]);
            }
            let expected = if expected.is_empty() {
                Value::Null
            } else {
                json!(expected)
            };
            assert_eq!(value(&store, "items"), expected, "{kind}-{suffix}");
            store.switch_branch("main").unwrap();
            assert_eq!(
                value(&store, "items"),
                json!([0, 1]),
                "child must not advance parent"
            );
        }
    }
}

#[test]
fn deleted_branch_is_not_resurrected_by_replay() {
    let dir = TempDir::new().unwrap();
    crash(dir.path(), "delete");
    let store = Store::open(config(dir.path())).unwrap();
    assert_eq!(store.list_branches().len(), 1);
    assert_eq!(value(&store, "items"), json!([0, 9]));
    assert_eq!(store.get_state_len("items").unwrap(), Some(2));
    let branch = store.create_empty_branch("gone", None).unwrap();
    assert!(branch.id.0 > 2, "deletion does not reuse identity");
    store.switch_branch("gone").unwrap();
    assert_eq!(value(&store, "items"), Value::Null);
}

#[test]
fn torn_tail_replays_only_complete_updates() {
    let dir = TempDir::new().unwrap();
    crash(dir.path(), "torn");
    let log_path = dir.path().join("records.log");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&log_path)
        .unwrap();
    file.set_len(file.metadata().unwrap().len() - 3).unwrap();
    drop(file);
    let store = Store::open(config(dir.path())).unwrap();
    assert_eq!(value(&store, "items"), json!([0, 1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(store.get_state_len("items").unwrap(), Some(9));
    assert!(store.recovery().is_some());
    store.set_auto_snapshot(false);
    append(&store, "items", json!(99));
    assert_eq!(store.current_branch().head, Sequence(10));
    assert_eq!(
        value(&store, "items"),
        json!([0, 1, 2, 3, 4, 5, 6, 7, 8, 99])
    );
}

#[test]
fn legacy_json_tail_replays_from_offset_zero() {
    let dir = TempDir::new().unwrap();
    {
        let store = Store::create(config(dir.path())).unwrap();
        register(&store, "items", log_strategy());
    }
    let log = RecordLog::open(dir.path().join("records.log")).unwrap();
    let update = StateUpdateRecord {
        record_id: RecordId(0),
        global_sequence: Sequence(1),
        state_id: "items".into(),
        prev_update_offset: None,
        operation: StateOperation::Append(b"42".to_vec()),
        timestamp: Timestamp(0),
    };
    let mut input = RecordInput::raw("state_update", serde_json::to_vec(&update).unwrap());
    input.encoding = PayloadEncoding::Raw;
    log.append(input, BranchId(1), Sequence(1)).unwrap();
    log.sync().unwrap();
    drop(log);
    let store = Store::open(config(dir.path())).unwrap();
    assert_eq!(value(&store, "items"), json!([42]));
    assert_eq!(store.get_state_len("items").unwrap(), Some(1));
}

#[test]
fn lost_legacy_registration_fails_explicitly_instead_of_opening_empty() {
    let dir = TempDir::new().unwrap();
    crash(dir.path(), "fresh");
    std::fs::remove_file(dir.path().join("state.bin")).unwrap();
    let before = std::fs::read(dir.path().join("records.log")).unwrap();
    let err = match Store::open(config(dir.path())) {
        Ok(_) => panic!("missing registration"),
        Err(e) => e,
    };
    assert!(
        matches!(&err, StoreError::Corruption(msg) if msg.contains("registration is missing")),
        "{err}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("records.log")).unwrap(),
        before
    );
}

#[test]
fn update_requires_a_durable_registration() {
    let dir = TempDir::new().unwrap();
    let store = Store::create(config(dir.path())).unwrap();
    assert!(matches!(
        store.update_state("unknown", StateOperation::Append(b"1".to_vec())),
        Err(StoreError::StateNotRegistered(_))
    ));
    assert_eq!(store.stats().unwrap().record_count, 0);
}

#[test]
fn partially_published_branch_cannot_leak_heads_into_a_new_empty_branch() {
    let dir = TempDir::new().unwrap();
    let store = Store::create(config(dir.path())).unwrap();
    register(&store, "items", log_strategy());
    append(&store, "items", json!(42));
    store.sync().unwrap();
    let previous_branches = std::fs::read(dir.path().join("branches.bin")).unwrap();
    let abandoned = store.create_branch("unpublished", None).unwrap();
    drop(store);

    // Model interruption after state.bin publication but before branches.bin.
    // The child has copied state heads, but no log record reserves its ID.
    std::fs::write(dir.path().join("branches.bin"), previous_branches).unwrap();
    let store = Store::open(config(dir.path())).unwrap();
    assert_eq!(store.list_branches().len(), 1);
    let new = store.create_empty_branch("new", None).unwrap();
    assert!(new.id > abandoned.id);
    store.switch_branch("new").unwrap();
    assert_eq!(value(&store, "items"), Value::Null);
    append(&store, "items", json!(99));
    assert_eq!(value(&store, "items"), json!([99]));
}
