use dashmap::DashMap;
use std::{collections::HashSet, ptr::from_ref, sync::Weak};
use tokio_util::sync::CancellationToken;

pub type KeyFingerprint = String;

pub struct SessionRegistry {
    sessions: DashMap<KeyFingerprint, Vec<CancellationToken>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self { sessions: DashMap::new() }
    }

    pub fn register(
        &self,
        fingerprint: KeyFingerprint,
        weak: Weak<Self>,
    ) -> (CancellationToken, SessionGuard) {
        let token = CancellationToken::new();
        self.sessions
            .entry(fingerprint.clone())
            .or_default()
            .push(token.clone());
        (token.clone(), SessionGuard { registry: weak, fingerprint, token })
    }

    fn unregister(&self, fingerprint: &str, token: &CancellationToken) {
        if let Some(mut tokens) = self.sessions.get_mut(fingerprint) {
            tokens.retain(|t| !std::ptr::eq(from_ref(t), from_ref(token)));
        }
    }

    pub fn kill_unlisted(&self, active_fingerprints: &HashSet<String>) {
        self.sessions.retain(|fingerprint, tokens| {
            if active_fingerprints.contains(fingerprint) {
                true
            } else {
                tokens.iter().for_each(CancellationToken::cancel);
                false
            }
        });
    }
}

pub struct SessionGuard {
    registry: Weak<SessionRegistry>,
    fingerprint: KeyFingerprint,
    token: CancellationToken,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.unregister(&self.fingerprint, &self.token);
        }
    }
}
