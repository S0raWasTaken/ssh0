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
    time::Duration,
};
use tokio::{runtime::Handle, time::sleep};

pub type AuthorizedKeys = Arc<RwLock<Arc<[PublicKey]>>>;

pub fn watch_authorized_keys(
    config_dir: &Path,
    sessions: Arc<SessionRegistry>,
) -> Res<AuthorizedKeys> {
    let authorized_keys_path = config_dir.join("authorized_keys");

    let keys = Arc::new(RwLock::new(
        load_authorized_keys(&authorized_keys_path)
            .inspect_err(|e| {
                print_err(e);
                log!(e "Using an empty authorized_keys list");
            })
            .unwrap_or_default()
            .into(),
    ));
    let keys_clone = Arc::clone(&keys);

    let tokio_handle = Handle::current();

    let mut watcher =
        recommended_watcher(move |event: notify::Result<Event>| {
            watch(
                event,
                &authorized_keys_path,
                &sessions,
                &keys_clone,
                &tokio_handle,
            );
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
    tokio_handle: &Handle,
) {
    let event = match event {
        Ok(event) => event,
        Err(e) => {
            print_err(&e);
            return;
        }
    };

    if !event.paths.iter().any(|p| p == authorized_keys_path) {
        return;
    }

    match event.kind {
        EventKind::Modify(_) | EventKind::Create(_) => {
            match load_authorized_keys(authorized_keys_path) {
                Ok(new_keys) => {
                    if let ControlFlow::Break(()) = check_atomic_save(
                        &new_keys,
                        authorized_keys_path,
                        sessions,
                        keys,
                        tokio_handle,
                    ) {
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

static EMPTY_CHECK_TASK: AtomicBool = AtomicBool::new(false);

fn check_atomic_save(
    new_keys: &[PublicKey],
    authorized_keys_path: &Path,
    sessions: &Arc<SessionRegistry>,
    keys: &AuthorizedKeys,
    tokio_handle: &Handle,
) -> ControlFlow<()> {
    if new_keys.is_empty() && !EMPTY_CHECK_TASK.swap(true, Relaxed) {
        let path = authorized_keys_path.to_path_buf();
        let sessions = Arc::clone(sessions);
        let keys = Arc::clone(keys);

        tokio_handle.spawn(async move {
            sleep(Duration::from_millis(10)).await;
            EMPTY_CHECK_TASK.store(false, Relaxed);

            recheck(&path, &sessions, &keys);
        });

        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

fn recheck(
    path: &Path,
    sessions: &Arc<SessionRegistry>,
    keys: &Arc<RwLock<Arc<[PublicKey]>>>,
) {
    if let Ok(recheck) = load_authorized_keys(path)
        && recheck.is_empty()
    {
        sessions.kill_all();
        *keys.write().unwrap() = Arc::from([]);
    }
}
