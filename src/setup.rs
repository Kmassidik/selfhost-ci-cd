//! The interactive setup wizard (PRD D2, D3, D15).
//!
//! This is the only component that is allowed to ask for elevated privileges, and it exits
//! before the server ever starts. Every prompt has a default, every choice is validated
//! before anything is written, and nothing is read from the environment.

use crate::auth;
use crate::config::{self, BuildConfig, Config, Ingress, Instance, Paths, Secrets, CONFIG_VERSION};
use crate::crypto::Vault;
use crate::probe::Probe;
use anyhow::{bail, Context, Result};
use std::io::{IsTerminal, Write};

pub struct Options {
    pub reconfigure: bool,
    pub teardown: bool,
    pub dry_run: bool,
}

pub fn run(paths: &Paths, opts: &Options) -> Result<()> {
    if opts.teardown {
        return teardown(paths);
    }
    if paths.exists() && !opts.reconfigure {
        bail!(
            "{} already exists.\n  Re-run the wizard:  cicd setup --reconfigure\n  Or remove it:        cicd setup --teardown",
            paths.config().display()
        );
    }

    println!("selfhost-ci-cd · setup");
    println!("─────────────────────\n");

    // ---- platform probe -------------------------------------------------
    let probe = Probe::detect();
    println!("Detected platform:");
    for line in probe.to_string().lines() {
        println!("  {line}");
    }
    if !probe.unavailable.is_empty() {
        println!(
            "  note: unreadable on this platform: {}",
            probe.unavailable.join(", ")
        );
    }
    println!();

    let existing: Option<(Config, Secrets, Vault)> = if opts.reconfigure && paths.exists() {
        let vault = Vault::load_or_create(&paths.master_key())?;
        let cfg = config::load_config(paths)?;
        let secrets = config::load_secrets(paths, &vault)?;
        Some((cfg, secrets, vault))
    } else {
        None
    };
    let pre = existing.as_ref().map(|(c, _, _)| c);

    // ---- ingress --------------------------------------------------------
    println!("Ingress — how browsers and webhooks reach this instance");
    println!("  1) lan          local network / localhost only, no domain (default)");
    println!("  2) cloudflare   provision a tunnel + DNS record via the Cloudflare API");
    println!("  3) direct       public hostname with ACME certificates");
    let default_mode = pre.map(|c| c.ingress.mode.as_str()).unwrap_or("lan");
    let mode_input = ask(
        "Choose",
        match default_mode {
            "cloudflare" => "2",
            "direct" => "3",
            _ => "1",
        },
    )?;
    let (mode, hostname) = match mode_input.trim() {
        "1" | "lan" => ("lan".to_string(), None),
        "2" | "cloudflare" => {
            println!();
            println!("  Cloudflare provisioning (tunnel + proxied CNAME) is milestone M2 and is");
            println!("  not in this build yet. Nothing has been written.");
            println!("  Re-run setup and choose 1 (lan) to continue testing locally.");
            bail!("cloudflare ingress is not implemented in this build");
        }
        "3" | "direct" => {
            println!();
            println!("  Direct ingress (ACME) is milestone M2 and is not in this build yet.");
            bail!("direct ingress is not implemented in this build");
        }
        other => bail!("unknown choice '{other}'"),
    };
    println!();

    // ---- instance -------------------------------------------------------
    let name = ask(
        "Instance name",
        pre.map(|c| c.instance.name.as_str()).unwrap_or("selfhost-ci-cd"),
    )?;
    let bind = ask(
        "Bind address (127.0.0.1 = local only, 0.0.0.0 = all interfaces)",
        pre.map(|c| c.instance.bind.as_str()).unwrap_or("127.0.0.1"),
    )?;
    let port: u16 = ask(
        "Port",
        &pre.map(|c| c.instance.port.to_string()).unwrap_or_else(|| "8080".into()),
    )?
    .parse()
    .context("port must be a number between 1 and 65535")?;
    println!();

    // ---- backends -------------------------------------------------------
    let has_docker = have_binary("docker");
    let has_nix = have_binary("nix");
    println!("Build backends detected: docker={} nix={}", yesno(has_docker), yesno(has_nix));
    let mut defaults: Vec<&str> = Vec::new();
    if has_docker {
        defaults.push("docker");
    }
    if has_nix {
        defaults.push("nix");
    }
    if defaults.is_empty() {
        defaults.push("docker");
        println!("  neither found on PATH — docker will be required at build time");
    }
    let backends_raw = ask("Backends (comma separated: docker,nix)", &defaults.join(","))?;
    let backends = parse_list(&backends_raw, &["docker", "nix"])?;
    println!();

    // ---- targets --------------------------------------------------------
    let targets_raw = ask(
        "Build targets (comma separated: linux,windows,android,macos)",
        &pre.map(|c| c.targets.join(",")).unwrap_or_else(|| "linux".into()),
    )?;
    let targets = parse_list(&targets_raw, &["linux", "windows", "android", "macos"])?;
    println!();

    // ---- admin ----------------------------------------------------------
    let admin_user = ask(
        "Admin username",
        pre.map(|c| c.instance.admin_user.as_str()).unwrap_or("admin"),
    )?;

    let password_hash = if opts.reconfigure && existing.is_some() {
        let keep = confirm("Keep the existing admin password?", true)?;
        if keep {
            existing.as_ref().unwrap().1.admin_password_hash.clone()
        } else {
            prompt_new_password(&admin_user)?
        }
    } else {
        prompt_new_password(&admin_user)?
    };
    println!();

    // ---- confirm --------------------------------------------------------
    println!("Summary");
    println!("  instance   {name}");
    println!("  ingress    {mode}");
    let listen = format!("{bind}:{port}");
    println!("  listen     {listen}");
    println!("  backends   {}", backends.join(", "));
    println!("  targets    {}", targets.join(", "));
    println!("  admin      {admin_user}");
    println!("  root       {}", paths.root.display());
    if !confirm("Write configuration?", true)? {
        println!("Nothing written.");
        return Ok(());
    }

    if opts.dry_run {
        println!("\ndry run: no files written");
        return Ok(());
    }

    // ---- write ----------------------------------------------------------
    std::fs::create_dir_all(&paths.root)
        .with_context(|| format!("cannot create {}", paths.root.display()))?;
    std::fs::create_dir_all(paths.data())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(paths.data(), std::fs::Permissions::from_mode(0o750))?;
    }

    // Capture provider tokens before `existing` is consumed, so rotating one secret does not
    // wipe the others.
    let old_providers = existing
        .as_ref()
        .map(|(_, s, _)| s.providers.clone())
        .unwrap_or_default();

    let vault = match existing {
        Some((_, _, v)) => v,
        None => Vault::load_or_create(&paths.master_key())?,
    };

    let cfg = Config {
        version: CONFIG_VERSION,
        instance: Instance {
            name,
            admin_user,
            bind,
            port,
            probe,
        },
        ingress: Ingress { mode, hostname },
        build: BuildConfig { backends },
        targets,
    };
    config::write_config(paths, &cfg)?;

    let secrets = Secrets {
        admin_password_hash: password_hash,
        session_secret: crate::crypto::random_token(32),
        providers: old_providers,
    };
    config::write_secrets(paths, &vault, &secrets)?;

    println!();
    println!("Written:");
    println!("  {}", paths.config().display());
    println!("  {}", paths.secrets().display());
    println!("  {} (mode 0400)", paths.master_key().display());
    println!();
    println!("Next:");
    println!("  cicd serve --root {}", paths.root.display());
    println!("  then open http://{listen}/login");
    Ok(())
}

fn prompt_new_password(user: &str) -> Result<String> {
    println!("Admin password rules: at least 12 characters, mixing at least 3 of");
    println!("lowercase / uppercase / digits / symbols. It is hashed with argon2id.");
    loop {
        let a = ask_secret("Admin password")?;
        if let Err(e) = auth::policy_check(&a, user) {
            println!("  rejected: {e}");
            continue;
        }
        let b = ask_secret("Repeat password")?;
        if a != b {
            println!("  rejected: passwords do not match");
            continue;
        }
        return Ok(auth::hash_password(&a)?);
    }
}

fn parse_list(input: &str, allowed: &[&str]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for raw in input.split(',') {
        let item = raw.trim().to_lowercase();
        if item.is_empty() {
            continue;
        }
        if !allowed.contains(&item.as_str()) {
            bail!("'{item}' is not one of: {}", allowed.join(", "));
        }
        if !out.contains(&item) {
            out.push(item);
        }
    }
    if out.is_empty() {
        bail!("choose at least one value from: {}", allowed.join(", "));
    }
    Ok(out)
}

fn teardown(paths: &Paths) -> Result<()> {
    if !paths.root.exists() {
        println!("{} does not exist, nothing to remove", paths.root.display());
        return Ok(());
    }
    println!("This removes the entire instance at {}", paths.root.display());
    println!("  config, sealed secrets, master key, and instance data");
    let typed = ask("Type 'delete' to confirm", "")?;
    if typed != "delete" {
        println!("Aborted.");
        return Ok(());
    }
    std::fs::remove_dir_all(&paths.root)?;
    println!("Removed {}", paths.root.display());
    Ok(())
}

fn yesno(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}

fn have_binary(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(name);
        candidate.is_file()
    })
}

// ------------------------------------------------------------------ prompts

fn read_line() -> Result<String> {
    let mut s = String::new();
    let n = std::io::stdin().read_line(&mut s)?;
    if n == 0 {
        bail!("input closed");
    }
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

fn ask(prompt: &str, default: &str) -> Result<String> {
    if default.is_empty() {
        print!("{prompt}: ");
    } else {
        print!("{prompt} [{default}]: ");
    }
    std::io::stdout().flush()?;
    let line = read_line()?;
    Ok(if line.is_empty() { default.to_string() } else { line })
}

fn ask_secret(prompt: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        Ok(rpassword::prompt_password(format!("{prompt}: "))?)
    } else {
        print!("{prompt}: ");
        std::io::stdout().flush()?;
        read_line()
    }
}

fn confirm(prompt: &str, default: bool) -> Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    print!("{prompt} [{hint}]: ");
    std::io::stdout().flush()?;
    let line = read_line()?.to_lowercase();
    Ok(match line.as_str() {
        "" => default,
        "y" | "yes" => true,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_parsing_validates_and_dedupes() {
        let v = parse_list("docker, nix, docker", &["docker", "nix"]).unwrap();
        assert_eq!(v, vec!["docker", "nix"]);
        assert!(parse_list("java", &["docker", "nix"]).is_err());
        assert!(parse_list(" , ", &["docker", "nix"]).is_err());
    }
}
