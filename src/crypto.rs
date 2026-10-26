//! Sealed secret storage (PRD D14 / SR-3).
//!
//! AES-256-GCM, nonce prefixed to the ciphertext, magic header for format identification.
//! The key never leaves this module except as raw bytes written straight to the master key
//! file with mode 0400.

use aes_gcm::aead::{Aead, Generate, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, bail, Result};
use rand::Rng;
use std::path::Path;

const MAGIC: &[u8; 4] = b"CCV1";
pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

pub struct Vault {
    key: Key<Aes256Gcm>,
}

impl Vault {
    pub fn generate() -> Self {
        Self { key: Key::<Aes256Gcm>::generate() }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_LEN {
            bail!("master key must be {KEY_LEN} bytes, got {}", bytes.len());
        }
        let key = Key::<Aes256Gcm>::try_from(bytes)
            .map_err(|_| anyhow!("master key must be {KEY_LEN} bytes"))?;
        Ok(Self { key })
    }

    /// Loads the key file, or creates it with mode 0400 if absent.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = std::fs::read(path)?;
            let vault = Self::from_slice(&raw)?;
            harden(path)?;
            return Ok(vault);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let vault = Self::generate();
        write_private(path, &vault.key_bytes())?;
        Ok(vault)
    }

    pub fn key_bytes(&self) -> Vec<u8> {
        self.key.to_vec()
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.key);
        let nonce = Nonce::generate();
        let ct = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("sealing failed: {e}"))?;
        let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < MAGIC.len() + NONCE_LEN {
            bail!("sealed blob is truncated");
        }
        if &blob[..MAGIC.len()] != MAGIC {
            bail!("sealed blob has an unknown format (wrong file, or not sealed)");
        }
        let nonce_bytes = &blob[MAGIC.len()..MAGIC.len() + NONCE_LEN];
        let ct = &blob[MAGIC.len() + NONCE_LEN..];
        let cipher = Aes256Gcm::new(&self.key);
        let nonce = Nonce::try_from(nonce_bytes)
            .map_err(|_| anyhow!("sealed blob has a malformed nonce"))?;
        cipher
            .decrypt(&nonce, ct)
            .map_err(|_| anyhow!("decryption failed: wrong master key or corrupted blob"))
    }
}

/// Cryptographically random, URL-safe token for sessions and CSRF.
pub fn random_token(len: usize) -> String {
    use base64::Engine as _;
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(unix)]
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o400)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(unix)]
fn harden(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip() {
        let v = Vault::generate();
        let blob = v.seal(b"ghp_secret_token").unwrap();
        assert_eq!(&blob[..4], b"CCV1");
        assert_eq!(v.open(&blob).unwrap(), b"ghp_secret_token");
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let v = Vault::generate();
        let blob = v.seal(b"super-secret-value").unwrap();
        assert!(!blob.windows(18).any(|w| w == b"super-secret-value"));
    }

    #[test]
    fn wrong_key_fails() {
        let a = Vault::generate();
        let b = Vault::generate();
        let blob = a.seal(b"x").unwrap();
        assert!(b.open(&blob).is_err());
    }

    #[test]
    fn nonces_differ_between_seals() {
        let v = Vault::generate();
        let a = v.seal(b"same").unwrap();
        let b = v.seal(b"same").unwrap();
        assert_ne!(a[4..16], b[4..16]);
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_bad_format() {
        let v = Vault::generate();
        assert!(v.open(b"plaintext").is_err());
        assert!(v.open(b"CCV1").is_err());
    }

    #[test]
    fn token_length_and_uniqueness() {
        let a = random_token(24);
        let b = random_token(24);
        assert_ne!(a, b);
        assert_eq!(a.len(), 32); // 24 bytes -> 32 base64 chars, no padding
    }
}
