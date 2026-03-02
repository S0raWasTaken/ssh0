use dashmap::DashMap;
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

pub struct RateLimiter {
    attempts: DashMap<IpAddr, (u32, Instant)>,
    max_attempts: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self { attempts: DashMap::new(), max_attempts, window }
    }

    pub fn increment(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut entry = self.attempts.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) > self.window {
            *entry = (0, now);
        }
        entry.0 += 1;
    }

    pub fn reset(&self, ip: IpAddr) {
        self.attempts.remove(&ip);
    }

    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        self.attempts.get(&ip).is_none_or(|entry| entry.0 < self.max_attempts)
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        self.attempts
            .retain(|_, (_, time)| now.duration_since(*time) < self.window);
    }
}
