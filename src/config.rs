//! Instance configuration and secret types.
//!
//! Two files, never one: `config.toml` is non-secret and world-readable, `secrets.sealed` is
//! the encrypted blob. Nothing in this project reads configuration from the environment
//! (PRD D2) — the CLI writes these files and the server reads them.

use crate::crypto::{self, Vault};
use crate::probe::Probe;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    pub instance: Instance,
    pub ingress: Ingress,
    pub build: BuildConfig,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub name: String,
    pub admin_user: String,
    pub bind: String,
    pub port: u16,
    pub probe: Probe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ingress {
    /// `lan`, `cloudflare`, or `direct`.
    pub mode: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    /// Subset of `docker`, `nix`.
    pub backends: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Secrets {
    pub admin_password_hash: String,
    pub session_secret: String,
    /// Named provider tokens, keyed by provider: `github`, `gitlab`, `gitea`, `cloudflare`,
    /// `registry`.
    pub providers: BTreeMap<String, String>,
}

pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    pub fn config(&self) -> PathBuf {
        self.root.join("config.toml")
    }
    pub fn secrets(&self) -> PathBuf {
        self.root.join("secrets.sealed")
    }
    pub fn master_key(&self) -> PathBuf {
        self.root.join("master.key")
    }
    pub fn data(&self) -> PathBuf {
        self.root.join("data")
    }
    pub fn exists(&self) -> bool {
        self.config().exists()
    }
}

pub fn load_config(paths: &Paths) -> Result<Config> {
    let text = std::fs::read_to_string(paths.config())
        .with_context(|| format!("cannot read {}", paths.config().display()))?;
    let cfg: Config = toml::from_str(&text).context("config.toml is not valid")?;
    if cfg.version != CONFIG_VERSION {
        bail!(
            "config.toml is version {}, this binary expects {CONFIG_VERSION}",
            cfg.version
        );
    }
    Ok(cfg)
}

pub fn write_config(paths: &Paths, cfg: &Config) -> Result<()> {
    std::fs::create_dir_all(&paths.root)?;
    let text = toml::to_string_pretty(cfg)?;
    std::fs::write(paths.config(), text)?;
    harden_config(&paths.config())?;
    Ok(())
}

pub fn load_secrets(paths: &Paths, vault: &Vault) -> Result<Secrets> {
    let blob = std::fs::read(paths.secrets())
        .with_context(|| format!("cannot read {}", paths.secrets().display()))?;
    let plain = vault.open(&blob)?;
    let secrets: Secrets = serde_json::from_slice(&plain).context("sealed secrets are malformed")?;
    Ok(secrets)
}

pub fn write_secrets(paths: &Paths, vault: &Vault, secrets: &Secrets) -> Result<()> {
    let plain = serde_json::to_vec(secrets)?;
    let blob = vault.seal(&plain)?;
    crypto::write_private(&paths.secrets(), &blob)?;
    Ok(())
}

#[cfg(unix)]
fn harden_config(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    Ok(())
}

#[cfg(not(unix))]
fn harden_config(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::Probe;

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cicd-test-{}", crypto::random_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_cfg() -> Config {
        Config {
            version: CONFIG_VERSION,
            instance: Instance {
                name: "test".into(),
                admin_user: "admin".into(),
                bind: "127.0.0.1".into(),
                port: 8080,
                probe: Probe {
                    os: "linux".into(), os_version: "x".into(), arch: "x86_64".into(),
                    pointer_width: 64, cpu_vendor: None, cpu_model: None,
                    x86_level: Some("v2".into()), cpu_flags: vec![], page_size: Some(4096),
                    ram_bytes: None, disk_bytes: None, kvm: Some(true), virt_flags: vec![],
                    tpm: Some(false), init_system: Some("systemd".into()), captured_at: 0,
                    unavailable: vec![],
                },
            },
            ingress: Ingress { mode: "lan".into(), hostname: None },
            build: BuildConfig { backends: vec!["docker".into()] },
            targets: vec!["linux".into()],
        }
    }

    #[test]
    fn config_roundtrip() {
        let dir = tmp();
        let paths = Paths::new(&dir);
        write_config(&paths, &sample_cfg()).unwrap();
        let back = load_config(&paths).unwrap();
        assert_eq!(back.instance.name, "test");
        assert_eq!(back.instance.probe.baseline(), "x86_64-v2");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secrets_roundtrip_and_absence_in_config() {
        let dir = tmp();
        let paths = Paths::new(&dir);
        let vault = Vault::generate();
        let mut s = Secrets::default();
        s.admin_password_hash = "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA".into();
        s.providers.insert("github".into(), "ghp_tok".into());
        write_secrets(&paths, &vault, &s).unwrap();

        let raw = std::fs::read(paths.secrets()).unwrap();
        assert!(!raw.windows(7).any(|w| w == b"ghp_tok"));

        let back = load_secrets(&paths, &vault).unwrap();
        assert_eq!(back.providers.get("github").unwrap(), "ghp_tok");
        std::fs::remove_dir_all(&dir).ok();
    }
}
