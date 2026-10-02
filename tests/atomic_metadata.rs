//! Every metadata saver publishes a new file, leaving an open previous
//! checkpoint intact. These tests fail against truncate-in-place saves.

use chronicle::{
    FieldIndexKind, StateOperation, StateRegistration, StateStrategy, Store, StoreConfig,
};
use same_file::Handle;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use tempfile::TempDir;

fn config(path: &Path) -> StoreConfig {
    StoreConfig {
        path: path.to_owned(),
        ..Default::default()
    }
}

fn append(store: &Store, timestamp: u64) {
    store
        .update_state(
            "messages",
            StateOperation::Append(format!("{{\"timestamp\":{timestamp}}}").into_bytes()),
        )
        .unwrap();
}

fn assert_published_without_truncating(name: &str) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("store");
    let store = Store::create(config(&path)).unwrap();
    store
        .register_state(StateRegistration {
            id: "messages".into(),
            strategy: StateStrategy::AppendLog {
                delta_snapshot_every: 100,
                full_snapshot_every: 100,
            },
            initial_value: None,
        })
        .unwrap();
    append(&store, 10);
    store
        .register_state_field_index("messages", "/timestamp", FieldIndexKind::Number)
        .unwrap();
    store.sync().unwrap();

    let checkpoint = path.join(name);
    let previous_bytes = fs::read(&checkpoint).unwrap();
    let mut previous_file = File::open(&checkpoint).unwrap();
    append(&store, 20);
    store.create_branch("feature", None).unwrap();
    store.sync().unwrap();

    let mut still_previous = Vec::new();
    previous_file.read_to_end(&mut still_previous).unwrap();
    assert_eq!(
        still_previous, previous_bytes,
        "{name} was overwritten in place"
    );
    assert_ne!(
        fs::read(&checkpoint).unwrap(),
        previous_bytes,
        "{name} did not advance"
    );
    drop(previous_file);
    drop(store);

    let reopened = Store::open(config(&path)).unwrap();
    assert_eq!(reopened.get_state_len("messages").unwrap(), Some(2));
    assert!(reopened.list_branches().iter().any(|b| b.name == "feature"));
    assert_eq!(
        reopened.query_state_index_range(
            "messages",
            "/timestamp",
            Some(10.0),
            Some(20.0),
            None,
            None,
            false
        ),
        Some(vec![0, 1]),
    );
}

#[test]
fn sync_only_republishes_metadata_that_changed() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("store");
    let store = Store::create(config(&path)).unwrap();
    store
        .register_state(StateRegistration {
            id: "messages".into(),
            strategy: StateStrategy::AppendLog {
                delta_snapshot_every: 100,
                full_snapshot_every: 100,
            },
            initial_value: None,
        })
        .unwrap();
    append(&store, 10);
    store
        .register_state_field_index("messages", "/timestamp", FieldIndexKind::Number)
        .unwrap();
    store.sync().unwrap();
    let names = ["state.bin", "state-indexes.bin", "branches.bin"];
    let identities = || names.map(|name| Handle::from_path(path.join(name)).unwrap());
    let first = identities();

    store.sync().unwrap();
    assert_eq!(
        identities(),
        first,
        "unchanged sync must not republish metadata"
    );

    store
        .append(chronicle::RecordInput::raw("message", b"raw".to_vec()))
        .unwrap();
    store.sync().unwrap();
    let raw = identities();
    assert_eq!(raw[0], first[0], "raw append leaves state metadata alone");
    assert_eq!(raw[1], first[1], "raw append leaves field indexes alone");
    assert_ne!(raw[2], first[2], "the new branch head must persist");

    append(&store, 20);
    store.sync().unwrap();
    let state = identities();
    for i in 0..names.len() {
        assert_ne!(state[i], raw[i], "{} changed", names[i]);
    }
    store.sync().unwrap();
    assert_eq!(identities(), state);

    drop(store);
    let reopened = Store::open(config(&path)).unwrap();
    // Loading bytes is not a durability acknowledgement from this writer.
    reopened.sync().unwrap();
    let loaded = identities();
    for i in 0..names.len() {
        assert_ne!(loaded[i], state[i], "{} first save after load", names[i]);
    }
    reopened.sync().unwrap();
    assert_eq!(identities(), loaded);
    assert_eq!(reopened.get_state_len("messages").unwrap(), Some(2));
}

#[test]
fn state_checkpoint_is_replaced() {
    assert_published_without_truncating("state.bin");
}

#[test]
fn branch_checkpoint_is_replaced() {
    assert_published_without_truncating("branches.bin");
}

#[test]
fn field_index_checkpoint_is_replaced() {
    assert_published_without_truncating("state-indexes.bin");
}
