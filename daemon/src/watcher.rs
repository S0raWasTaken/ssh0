use crate::{Res, fingerprint, print_err, sessions::SessionRegistry};
use libssh0::log;
use notify::{
    Event, EventKind, RecursiveMode::NonRecursive, Watcher, recommended_watcher,
};
use ssh_key::PublicKey;
use std::{
    ops::ControlFlow,
    path::Path,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
};

pub type AuthorizedKeys = Arc<RwLock<Arc<[PublicKey]>>>;

pub fn watch_authorized_keys(
    config_dir: &Path,
    sessions: Arc<SessionRegistry>,
) -> Res<AuthorizedKeys> {
    let authorized_keys_path = config_dir.join("authorized_keys");

    let keys = Arc::new(RwLock::new(
        load_authorized_keys(&authorized_keys_path).unwrap_or_default().into(),
    ));
    let keys_clone = Arc::clone(&keys);

    let mut watcher =
        recommended_watcher(move |event: notify::Result<Event>| {
            watch(event, &authorized_keys_path, &sessions, &keys_clone);
        })?;

    watcher.watch(config_dir, NonRecursive)?;

    Box::leak(Box::new(watcher));

    Ok(keys)
}

fn watch(
    event: notify::Result<Event>,
    authorized_keys_path: &Path,
    sessions: &Arc<SessionRegistry>,
    keys: &AuthorizedKeys,
) {
    let Ok(event) = event else { return };

    if !event.paths.iter().any(|p| p == authorized_keys_path) {
        return;
    }

    match event.kind {
        EventKind::Modify(_) | EventKind::Create(_) => {
            match load_authorized_keys(authorized_keys_path) {
                Ok(new_keys) => {
                    if let ControlFlow::Break(()) = check_atomic_save(&new_keys)
                    {
                        return;
                    }

                    let new_fingerprints =
                        new_keys.iter().map(fingerprint).collect();

                    *keys.write().unwrap() = new_keys.into();

                    sessions.kill_unlisted(&new_fingerprints);
                }
                Err(e) => print_err(&e),
            }
        }
        EventKind::Remove(_) => {
            sessions.kill_all();
            *keys.write().unwrap() = Arc::from([]);
            log!(e "authorized_keys deleted — all sessions killed, no new connections allowed");
        }
        _ => {}
    }
}

fn load_authorized_keys(authorized_keys_path: &Path) -> Res<Vec<PublicKey>> {
    Ok(ssh_key::AuthorizedKeys::read_file(authorized_keys_path)?
        .iter()
        .map(|e| e.public_key().clone())
        .collect::<Vec<_>>())
}

// Most text editors save files in two steps (truncate then write),
// which is why we ignore the first empty reload.
//
// Although, this introduces an issue where intentionally emptying
// the file would not kill all active connections, since now only a
// single step happens, which is the truncation step.
//
// The user shall be instructed to delete `authorized_keys` (or save it twice)
// if he actually wants to kill all active sessions.

static EMPTY_SEEN: AtomicBool = AtomicBool::new(false);

fn check_atomic_save(new_keys: &[PublicKey]) -> ControlFlow<()> {
    if new_keys.is_empty() {
        if !EMPTY_SEEN.swap(true, Relaxed) {
            return ControlFlow::Break(());
        }
    } else {
        EMPTY_SEEN.store(false, Relaxed);
    }
    ControlFlow::Continue(())
}
