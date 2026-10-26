# selfhost-ci-cd

Self-hosted CI/CD that installs with one privileged command, configures itself through an
interactive terminal wizard, and builds for Linux, Windows, Android and macOS.

Specification: [`PRD.md`](PRD.md). Constraints for contributors: [`AGENTS.md`](AGENTS.md).

**Status:** `1.0.0-alpha.1` — milestones M0 and the M1 shell are done. See the table below.

## Quick start (local test)

```sh
cargo build
./target/debug/cicd probe                  # platform + CPU baseline detection
./target/debug/cicd setup --root ./devdata # interactive wizard
./target/debug/cicd doctor --root ./devdata
./target/debug/cicd serve  --root ./devdata
# open http://127.0.0.1:8080/login
```

`--root` exists so you can run an instance without touching `/etc`. The default root is
`/etc/cicd`, which needs `sudo`.

To remove an instance: `cicd setup --teardown --root ./devdata`.

## What works now

| Area | State |
|---|---|
| Platform probe: OS, arch, x86-64 level, flags, page size, RAM/disk, KVM, TPM, init | ✅ |
| Sealed secret store (AES-256-GCM), master key `0400 root` | ✅ |
| `config.toml` + `secrets.sealed`, no `.env`, nothing read from the environment | ✅ |
| Interactive setup wizard with validation and `--dry-run` / `--reconfigure` / `--teardown` | ✅ |
| `probe`, `doctor`, `status`, `serve` commands | ✅ |
| SSR login, argon2id, sessions, CSRF, lockout after 5 failures | ✅ |
| Security headers, no client-side JavaScript, uniform 404 | ✅ |
| Cloudflare tunnel + DNS provisioning (M2) | ⬜ |
| Webhooks, queue, agent protocol, logs (M3) | ⬜ |
| Linux builds with Docker and Nix (M4) | ⬜ |
| Local registry, artifacts (M5) | ⬜ |
| Android / Windows / macOS targets (M6–M8) | ⬜ |

## Design constraints you should know

- **No `.env`, ever.** The wizard is the only configuration surface. Setting `GITHUB_TOKEN`
  or similar has no effect.
- **`sudo` only inside `cicd setup`.** The server, agents and builds run unprivileged.
- **Architecture is probed, never assumed.** `x86_64-v1`/`v2`/`v3`/`v4` and `aarch64-v8.0`
  are detected from CPUID/flags; distributed artifacts target the lowest supported baseline.
- **SSR only.** Pages are server-rendered from Askama templates and there is no JSON API and
  no JavaScript bundle, so there is no route table for a scanner to enumerate.
- **Version line is `1.x.x`** until this ships. No v2 roadmap.

## Layout

```
src/probe.rs     platform + CPU detection, baseline calculation
src/crypto.rs    AES-256-GCM sealing, master key handling, token generation
src/config.rs    config.toml and sealed secrets
src/auth.rs      argon2id, password policy, sessions, lockout
src/setup.rs     the interactive wizard
src/server.rs    SSR routes, security headers
templates/       Askama templates
assets/          stylesheet (the only static asset)
```

## Tests

```sh
cargo test
```

Covers CPU-level classification (including Linux's `pni` spelling of SSE3), sealing
round-trips and wrong-key failure, config/secrets round-trips, password policy, session
revocation, and lockout thresholds.
# selfhost-ci-cd
