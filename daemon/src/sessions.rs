use dashmap::DashMap;
use libssh0::{common::SessionType, log};
use std::{
    collections::HashSet,
    fmt::Display,
    net::SocketAddr,
    sync::{
        Weak,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio_util::sync::CancellationToken;

pub type KeyFingerprint = String;

#[derive(Clone)]
pub struct SessionInfo {
    pub id: usize,
    pub address: SocketAddr,
    pub token: CancellationToken,
}

impl Display for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session {} on {}", self.id, self.address)
    }
}

impl SessionInfo {
    pub fn new(
        id: usize,
        address: SocketAddr,
        token: CancellationToken,
    ) -> Self {
        Self { id, address, token }
    }

    pub fn cancel(&self, reason: &str) {
        self.token.cancel();
        log!(e "{self} killed by: {reason}");
    }
}

pub struct SessionRegistry {
    sessions: DashMap<KeyFingerprint, Vec<SessionInfo>>,
    counter: AtomicUsize,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self { sessions: DashMap::new(), counter: AtomicUsize::default() }
    }

    pub fn register(
        &self,
        fingerprint: KeyFingerprint,
        weak: Weak<Self>,
        address: SocketAddr,
        session_type: SessionType,
    ) -> (SessionInfo, SessionGuard) {
        let session = SessionInfo::new(
            self.counter.fetch_add(1, Ordering::Relaxed),
            address,
            CancellationToken::new(),
        );

        log!("{session_type} {session} opened");

        self.sessions
            .entry(fingerprint.clone())
            .or_default()
            .push(session.clone());
        (session.clone(), SessionGuard { registry: weak, fingerprint, session })
    }

    pub fn kill_unlisted(&self, active_fingerprints: &HashSet<String>) {
        self.sessions.retain(|fingerprint, tokens| {
            if active_fingerprints.contains(fingerprint) {
                true
            } else {
                #[expect(clippy::needless_for_each, reason = "Less nesting")]
                tokens.iter().for_each(|s| s.cancel("authorized_keys change"));
                false
            }
        });
    }

    pub fn kill_all(&self) {
        for entry in &self.sessions {
            entry
                .value()
                .iter()
                .for_each(|session| session.cancel("called `kill_all`"));
        }

        self.sessions.clear();
    }

    fn unregister(&self, fingerprint: &str, id: usize) {
        if let Some(mut tokens) = self.sessions.get_mut(fingerprint) {
            tokens.retain(|info| info.id != id);
        }
    }
}

pub struct SessionGuard {
    registry: Weak<SessionRegistry>,
    fingerprint: KeyFingerprint,
    session: SessionInfo,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.unregister(&self.fingerprint, self.session.id);
        }
    }
}
