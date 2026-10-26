//! Password policy, argon2id hashing, session store and login throttling.
//!
//! Password-only admin auth is a locked decision (PRD D9), which puts the entire burden on
//! this file: strict policy, memory-hard hashing, per-user lockout, server-side sessions with
//! rotation, and constant-time verification.

use anyhow::{bail, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MIN_LEN: usize = 12;
pub const MAX_LEN: usize = 256;
pub const MAX_FAILURES: u32 = 5;
pub const LOCKOUT: Duration = Duration::from_secs(300);
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);
pub const CSRF_TTL: Duration = Duration::from_secs(10 * 60);

/// A short list of passwords that must never be accepted, regardless of length.
const BANNED: &[&str] = &[
    "password", "password1", "password123", "passw0rd", "administrator", "letmein",
    "qwertyuiop", "123456789012", "changeme", "changeme123", "cicdcicdcicd",
    "selfhostcicd", "iloveyou123", "adminadmin12",
];

pub fn policy_check(password: &str, username: &str) -> Result<()> {
    let len = password.chars().count();
    if len < MIN_LEN {
        bail!("password must be at least {MIN_LEN} characters (got {len})");
    }
    if len > MAX_LEN {
        bail!("password must be at most {MAX_LEN} characters");
    }
    let classes = [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if classes < 3 {
        bail!("password must mix at least 3 of: lowercase, uppercase, digits, symbols");
    }
    let lower = password.to_ascii_lowercase();
    if BANNED.iter().any(|b| lower.contains(b)) {
        bail!("password contains a well-known weak phrase");
    }
    if !username.is_empty() && lower.contains(&username.to_ascii_lowercase()) {
        bail!("password must not contain the username");
    }
    if password.chars().all(|c| c == password.chars().next().unwrap()) {
        bail!("password must not be a single repeated character");
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String> {
    let hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Constant-time verification. A malformed stored hash is a failure, never a pass.
pub fn verify_password(password: &str, stored: &str) -> bool {
    let parsed = match PasswordHash::new(stored) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[derive(Clone, Debug)]
pub struct Session {
    pub user: String,
    pub csrf: String,
    pub expires: Instant,
}

impl Session {
    pub fn valid(&self) -> bool {
        Instant::now() < self.expires
    }
}

#[derive(Default)]
pub struct Sessions {
    inner: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    /// Creates a session and returns `(session_id, csrf_token)`.
    pub fn create(&self, user: &str) -> (String, String) {
        let sid = crate::crypto::random_token(32);
        let csrf = crate::crypto::random_token(32);
        let session = Session {
            user: user.to_string(),
            csrf: csrf.clone(),
            expires: Instant::now() + SESSION_TTL,
        };
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, s| s.valid()); // opportunistically drop expired sessions
        map.insert(sid.clone(), session);
        (sid, csrf)
    }

    pub fn get(&self, sid: &str) -> Option<Session> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(sid) {
            Some(s) if s.valid() => Some(s.clone()),
            Some(_) => {
                map.remove(sid);
                None
            }
            None => None,
        }
    }

    pub fn destroy(&self, sid: &str) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).remove(sid);
    }

    /// Revokes every session for a user. Wired into SR-14 (admin credential change); kept
    /// here so the invariant lives with the store that owns it.
    #[allow(dead_code)]
    pub fn destroy_all_for(&self, user: &str) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, s| s.user != user);
    }

    pub fn count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[derive(Default)]
pub struct Throttle {
    inner: Mutex<HashMap<String, Attempt>>,
}

#[derive(Clone, Copy, Debug)]
struct Attempt {
    failures: u32,
    locked_until: Option<Instant>,
}

pub enum LockState {
    Open,
    Locked(Duration),
}

impl Throttle {
    pub fn check(&self, key: &str) -> LockState {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(key) {
            Some(a) => match a.locked_until {
                Some(until) if Instant::now() < until => {
                    LockState::Locked(until.duration_since(Instant::now()))
                }
                _ => LockState::Open,
            },
            None => LockState::Open,
        }
    }

    /// Records a failure and returns the remaining attempts before lockout.
    pub fn fail(&self, key: &str) -> u32 {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(key.to_string()).or_insert(Attempt {
            failures: 0,
            locked_until: None,
        });
        entry.failures += 1;
        if entry.failures >= MAX_FAILURES {
            entry.locked_until = Some(Instant::now() + LOCKOUT);
            entry.failures = 0;
            return 0;
        }
        MAX_FAILURES - entry.failures
    }

    pub fn clear(&self, key: &str) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_accepts_a_strong_password() {
        assert!(policy_check("Correct-Horse-9-Battery", "admin").is_ok());
    }

    #[test]
    fn policy_rejects_short() {
        assert!(policy_check("Sh0rt!pass", "admin").is_err());
    }

    #[test]
    fn policy_rejects_single_class() {
        assert!(policy_check("abcdefghijklmnop", "admin").is_err());
    }

    #[test]
    fn policy_rejects_username_inside() {
        assert!(policy_check("Admin-Secret-99", "admin").is_err());
    }

    #[test]
    fn policy_rejects_known_weak_phrase() {
        assert!(policy_check("MyPassword123!x", "admin").is_err());
    }

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hash_password("Correct-Horse-9-Battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("Correct-Horse-9-Battery", &h));
        assert!(!verify_password("wrong", &h));
        assert!(!verify_password("Correct-Horse-9-Battery", "not-a-hash"));
    }

    #[test]
    fn hashes_are_salted() {
        let a = hash_password("Correct-Horse-9-Battery").unwrap();
        let b = hash_password("Correct-Horse-9-Battery").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn session_lifecycle() {
        let s = Sessions::default();
        let (sid, csrf) = s.create("admin");
        assert_eq!(s.get(&sid).unwrap().csrf, csrf);
        s.destroy(&sid);
        assert!(s.get(&sid).is_none());
    }

    #[test]
    fn sessions_can_be_revoked_per_user() {
        let s = Sessions::default();
        let (a, _) = s.create("admin");
        let (b, _) = s.create("admin");
        assert_eq!(s.count(), 2);
        s.destroy_all_for("admin");
        assert!(s.get(&a).is_none());
        assert!(s.get(&b).is_none());
    }

    #[test]
    fn throttle_locks_after_max_failures() {
        let t = Throttle::default();
        for _ in 0..MAX_FAILURES - 1 {
            assert!(t.fail("admin") > 0);
        }
        assert_eq!(t.fail("admin"), 0);
        assert!(matches!(t.check("admin"), LockState::Locked(_)));
        t.clear("admin");
        assert!(matches!(t.check("admin"), LockState::Open));
    }
}
