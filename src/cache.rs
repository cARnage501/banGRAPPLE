use std::env;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DAILY_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

pub fn cache_root() -> PathBuf {
    if let Some(path) = env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(path).join("ban-grapple");
    }

    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(".cache/ban-grapple");
    }

    PathBuf::from(".ban-grapple-cache")
}

pub fn current_epoch_secs() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

pub fn is_cache_fresh(fetched_at_epoch_secs: u64, ttl: Duration) -> bool {
    current_epoch_secs()
        .map(|now| now.saturating_sub(fetched_at_epoch_secs) < ttl.as_secs())
        .unwrap_or(false)
}
