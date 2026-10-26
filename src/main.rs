mod auth;
mod config;
mod crypto;
mod probe;
mod server;
mod setup;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cicd", version, about = "selfhost-ci-cd — self-hosted CI/CD", long_about = None)]
struct Cli {
    /// Instance root: config.toml, secrets.sealed, master.key, data/
    #[arg(long, global = true, default_value = "/etc/cicd")]
    root: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Interactive setup wizard (elevated when using the default root)
    Setup {
        /// Re-run the wizard, keeping existing values as defaults
        #[arg(long)]
        reconfigure: bool,
        /// Remove the instance directory
        #[arg(long)]
        teardown: bool,
        /// Print what would be written, write nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the detected platform, CPU level and baseline
    Probe,
    /// Verify the installation is healthy
    Doctor,
    /// Show the configured instance
    Status,
    /// Run the server in the foreground
    Serve,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let paths = config::Paths::new(&cli.root);

    match cli.command {
        Command::Probe => {
            print!("{}", probe::Probe::detect());
            Ok(())
        }
        Command::Setup { reconfigure, teardown, dry_run } => {
            setup::run(&paths, &setup::Options { reconfigure, teardown, dry_run })
        }
        Command::Status => status(&paths),
        Command::Doctor => doctor(&paths),
        Command::Serve => serve(&paths),
    }
}

fn status(paths: &config::Paths) -> Result<()> {
    if !paths.exists() {
        bail!(
            "no instance at {} — run: cicd setup --root {}",
            paths.root.display(),
            paths.root.display()
        );
    }
    let cfg = config::load_config(paths)?;
    println!("instance   {}", cfg.instance.name);
    println!("admin      {}", cfg.instance.admin_user);
    println!("listen     {}:{}", cfg.instance.bind, cfg.instance.port);
    println!("ingress    {}", cfg.ingress.mode);
    if let Some(h) = &cfg.ingress.hostname {
        println!("hostname   {h}");
    }
    println!("backends   {}", cfg.build.backends.join(", "));
    println!("targets    {}", cfg.targets.join(", "));
    println!("baseline   {}", cfg.instance.probe.baseline());
    println!("root       {}", paths.root.display());
    Ok(())
}

fn doctor(paths: &config::Paths) -> Result<()> {
    let mut failures = 0usize;
    let mut check = |ok: bool, label: &str, detail: String| {
        if ok {
            println!("  ok    {label:<24} {detail}");
        } else {
            failures += 1;
            println!("  FAIL  {label:<24} {detail}");
        }
    };

    let probe = probe::Probe::detect();
    println!("platform");
    println!("  {:<24} {} → {}", "baseline", probe.arch, probe.baseline());
    if let Some(l) = &probe.x86_level {
        println!("  {:<24} {l}", "x86-64 level");
    }
    check(
        probe.page_size.is_some(),
        "page size",
        probe.page_size.map(|v| v.to_string()).unwrap_or_else(|| "unknown".into()),
    );
    if !probe.unavailable.is_empty() {
        println!("  note  unreadable             {}", probe.unavailable.join(", "));
    }

    println!("\ninstance");
    check(paths.exists(), "config.toml", paths.config().display().to_string());
    check(paths.master_key().exists(), "master.key", paths.master_key().display().to_string());
    check(paths.secrets().exists(), "secrets.sealed", paths.secrets().display().to_string());

    if paths.exists() {
        match (config::load_config(paths), paths.master_key().exists()) {
            (Ok(cfg), true) => {
                match crypto::Vault::load_or_create(&paths.master_key())
                    .and_then(|v| config::load_secrets(paths, &v))
                {
                    Ok(secrets) => {
                        check(true, "secrets decrypt", format!("{} provider(s)", secrets.providers.len()));
                        check(
                            auth::verify_password("\0definitely-not-the-password", &secrets.admin_password_hash) == false,
                            "password hash",
                            "argon2id, does not accept a wrong password".into(),
                        );
                        let addr = format!("{}:{}", cfg.instance.bind, cfg.instance.port);
                        let free = std::net::TcpListener::bind(&addr).is_ok();
                        check(free, "bind available", addr);
                        for b in &cfg.build.backends {
                            let found = binary_on_path(b);
                            check(found, &format!("backend {b}"), if found { "found".into() } else { "not on PATH".into() });
                        }
                    }
                    Err(e) => check(false, "secrets decrypt", format!("{e}")),
                }
            }
            (Err(e), _) => check(false, "config.toml", format!("{e}")),
            (_, false) => check(false, "master.key", "missing".into()),
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(paths.master_key()) {
            let mode = meta.permissions().mode() & 0o777;
            check(mode == 0o400, "master.key mode", format!("{mode:o} (want 400)"));
        }
    }

    println!();
    if failures == 0 {
        println!("all checks passed");
        Ok(())
    } else {
        bail!("{failures} check(s) failed");
    }
}

fn serve(paths: &config::Paths) -> Result<()> {
    if !paths.exists() {
        bail!(
            "no instance at {} — run: cicd setup --root {}",
            paths.root.display(),
            paths.root.display()
        );
    }
    let cfg = config::load_config(paths)?;
    let vault = crypto::Vault::load_or_create(&paths.master_key())
        .context("cannot open the master key")?;
    let secrets = config::load_secrets(paths, &vault)
        .context("cannot decrypt secrets.sealed with this master key")?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(server::serve(cfg, secrets))
}

fn binary_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
        .unwrap_or(false)
}
