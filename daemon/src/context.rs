use crate::{
    Res, fingerprint,
    rate_limit::RateLimiter,
    sessions::{KeyFingerprint, SessionGuard, SessionInfo, SessionRegistry},
    watcher::AuthorizedKeys,
};
use std::{fmt::Display, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{spawn, sync::Semaphore, time::sleep};
use tokio_rustls::TlsAcceptor;

pub struct HostAndPort {
    host: String,
    port: u16,
}
impl Display for HostAndPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl HostAndPort {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    pub fn inner(&self) -> (&str, u16) {
        (&self.host, self.port)
    }
}

pub struct Context {
    pub acceptor: TlsAcceptor,
    pub authorized_keys: AuthorizedKeys,
    pub rate_limiter: Arc<RateLimiter>,
    pub semaphore: Arc<Semaphore>,
    pub host_and_port: HostAndPort,
    pub sessions: Arc<SessionRegistry>,
}

impl Context {
    pub fn new(
        acceptor: TlsAcceptor,
        authorized_keys: AuthorizedKeys,
        rate_limiter: RateLimiter,
        semaphore: Semaphore,
        host_and_port: HostAndPort,
        sessions: Arc<SessionRegistry>,
    ) -> Arc<Self> {
        Arc::new(Self {
            acceptor,
            authorized_keys,
            rate_limiter: Arc::new(rate_limiter),
            semaphore: Arc::new(semaphore),
            host_and_port,
            sessions,
        })
    }

    pub fn spawn_rate_limiter_task(&self) {
        let rl = Arc::clone(&self.rate_limiter);
        spawn(rate_limiter_cleanup_task(rl));
    }

    pub fn register_session(
        &self,
        fingerprint: KeyFingerprint,
        address: SocketAddr,
    ) -> Res<(SessionInfo, SessionGuard)> {
        self.recheck_auth(&fingerprint)?;

        let weak = Arc::downgrade(&self.sessions);
        Ok(self.sessions.register(fingerprint, weak, address))
    }

    fn recheck_auth(&self, key_fingerprint: &str) -> Res<()> {
        let still_authorized = self
            .authorized_keys
            .read()
            .unwrap()
            .iter()
            .any(|k| fingerprint(k) == key_fingerprint);

        if !still_authorized {
            return Err("Key revoked during authentication".into());
        }
        Ok(())
    }
}

async fn rate_limiter_cleanup_task(rate_limiter: Arc<RateLimiter>) {
    loop {
        sleep(Duration::from_mins(5)).await;
        rate_limiter.cleanup();
    }
}
