//! Cloudflare preflight and provisioning.
//!
//! Two rules drive this module:
//!
//! 1. **Refuse rather than half-provision.** If the hostname already has a DNS record, or a
//!    tunnel with our name exists, setup stops before writing anything and prints the exact
//!    steps to remove the conflict.
//! 2. **No separate base URL.** Once provisioning succeeds the dashboard is simply served at
//!    `https://<hostname>`; the URL is derived, never configured a second time.
//!
//! Verified against Cloudflare's API docs: token needs `Account → Cloudflare Tunnel → Edit`
//! and `Zone → DNS → Edit`, plus `Zone → Zone → Read` to resolve the zone name.

use anyhow::{bail, Result};
use serde_json::{json, Value};

pub const API: &str = "https://api.cloudflare.com/client/v4";
const USER_AGENT: &str = concat!("cicd/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone)]
pub struct Zone {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub id: String,
    pub rtype: String,
    pub content: String,
    pub proxied: bool,
}

#[derive(Debug, Clone)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub status: String,
    pub connections: usize,
}

/// A blocking, read-mostly Cloudflare v4 client.
pub struct Cf {
    agent: ureq::Agent,
    token: String,
}

impl Cf {
    pub fn new(token: impl Into<String>) -> Self {
        // Statuses are handled by this module, not turned into opaque errors, so Cloudflare's
        // error envelope can always be read and reported.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .user_agent(USER_AGENT)
            .http_status_as_error(false)
            .build()
            .into();
        Self { agent, token: token.into() }
    }

    fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let url = format!("{API}{path}");
        let auth = || format!("Bearer {}", self.token);
        let resp = match (method, body) {
            ("GET", _) => self.agent.get(&url).header("Authorization", auth()).call(),
            ("DELETE", _) => self.agent.delete(&url).header("Authorization", auth()).call(),
            ("POST", Some(b)) => self.agent.post(&url).header("Authorization", auth()).send_json(b),
            ("PUT", Some(b)) => self.agent.put(&url).header("Authorization", auth()).send_json(b),
            (m, None) => bail!("{m} {path} needs a body"),
            (m, _) => bail!("unsupported method {m}"),
        }
        .map_err(|e| anyhow::anyhow!("request to {path} failed: {e}"))?;

        let status = resp.status().as_u16();
        let mut resp = resp;
        let value: Value = resp.body_mut().read_json().unwrap_or(Value::Null);

        if status >= 400 {
            bail!(describe_error(status, &value));
        }
        if value.get("success").and_then(Value::as_bool) == Some(false) {
            bail!(describe_error(status, &value));
        }
        Ok(value.get("result").cloned().unwrap_or(Value::Null))
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        self.request("GET", path, None)
    }

    pub fn post(&self, path: &str, body: Value) -> Result<Value> {
        self.request("POST", path, Some(body))
    }

    pub fn put(&self, path: &str, body: Value) -> Result<Value> {
        self.request("PUT", path, Some(body))
    }

    pub fn delete(&self, path: &str) -> Result<Value> {
        self.request("DELETE", path, None)
    }

    // ------------------------------------------------------------ lookups

    pub fn zone(&self, name: &str) -> Result<Zone> {
        let v = self.get(&format!("/zones?name={}&per_page=50", enc(name)))?;
        let arr = v.as_array().cloned().unwrap_or_default();
        let found = arr.iter().find(|z| {
            z.get("name").and_then(Value::as_str) == Some(name)
        });
        match found {
            Some(z) => Ok(Zone {
                id: str_field(z, "id"),
                name: name.to_string(),
            }),
            None => bail!(
                "zone `{name}` not found for this token.\n  \
                 Check the zone name is exactly as it appears in the Cloudflare dashboard, and that\n  \
                 the token has permission `Zone → Zone → Read` on it."
            ),
        }
    }

    pub fn account(&self, want: Option<&str>) -> Result<String> {
        let v = self.get("/accounts?per_page=50")?;
        let arr = v.as_array().cloned().unwrap_or_default();
        let ids: Vec<String> = arr.iter().map(|a| str_field(a, "id")).collect();
        match want {
            Some(id) if ids.iter().any(|x| x == id) => Ok(id.to_string()),
            Some(id) => bail!(
                "account id `{id}` is not visible to this token (visible: {}).\n  \
                 The token needs `Account → Cloudflare Tunnel → Edit` on that account.",
                if ids.is_empty() { "none".to_string() } else { ids.join(", ") }
            ),
            None => match ids.len() {
                0 => bail!(
                    "no account visible to this token.\n  \
                     Create the token under the account you want to use, with\n  \
                     `Account → Cloudflare Tunnel → Edit` and `Account → Account Settings → Read`."
                ),
                1 => Ok(ids[0].clone()),
                _ => bail!(
                    "several accounts are visible ({}); pass one explicitly with --account",
                    ids.join(", ")
                ),
            },
        }
    }

    /// Exact-match DNS records at `hostname` (any type — an A record blocks the CNAME too).
    pub fn dns_at(&self, zone_id: &str, hostname: &str) -> Result<Vec<Record>> {
        let v = self.get(&format!(
            "/zones/{zone_id}/dns_records?name={}&per_page=100",
            enc(hostname)
        ))?;
        let arr = v.as_array().cloned().unwrap_or_default();
        Ok(arr
            .iter()
            .filter(|r| {
                r.get("name")
                    .and_then(Value::as_str)
                    .map(|n| n.eq_ignore_ascii_case(hostname))
                    .unwrap_or(false)
            })
            .map(|r| Record {
                id: str_field(r, "id"),
                rtype: str_field(r, "type"),
                content: r.get("content").and_then(Value::as_str).unwrap_or("").to_string(),
                proxied: r.get("proxied").and_then(Value::as_bool).unwrap_or(false),
            })
            .collect())
    }

    pub fn tunnel_by_name(&self, account: &str, name: &str) -> Result<Option<Tunnel>> {
        let v = self.get(&format!(
            "/accounts/{account}/cfd_tunnel?name={}&is_deleted=false&per_page=50",
            enc(name)
        ))?;
        let arr = v.as_array().cloned().unwrap_or_default();
        Ok(arr
            .iter()
            .find(|t| t.get("name").and_then(Value::as_str) == Some(name))
            .map(|t| Tunnel {
                id: str_field(t, "id"),
                name: name.to_string(),
                status: t.get("status").and_then(Value::as_str).unwrap_or("unknown").to_string(),
                connections: t
                    .get("connections")
                    .and_then(Value::as_array)
                    .map(|a| a.len())
                    .unwrap_or(0),
            }))
    }

    // ------------------------------------------------------------ mutations

    pub fn create_tunnel(&self, account: &str, name: &str) -> Result<(String, Option<String>)> {
        let v = self.post(
            &format!("/accounts/{account}/cfd_tunnel"),
            json!({ "name": name, "config_src": "cloudflare" }),
        )?;
        let id = str_field(&v, "id");
        let token = v.get("token").and_then(Value::as_str).map(str::to_string);
        Ok((id, token))
    }

    pub fn tunnel_token(&self, account: &str, tunnel_id: &str) -> Result<String> {
        let v = self.get(&format!("/accounts/{account}/cfd_tunnel/{tunnel_id}/token"))?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("tunnel token endpoint returned no token"))
    }

    pub fn set_ingress(&self, account: &str, tunnel_id: &str, hostname: &str, service: &str) -> Result<()> {
        self.put(
            &format!("/accounts/{account}/cfd_tunnel/{tunnel_id}/configurations"),
            json!({
                "config": {
                    "ingress": [
                        { "hostname": hostname, "service": service },
                        { "service": "http_status:404" }
                    ]
                }
            }),
        )?;
        Ok(())
    }

    pub fn create_cname(&self, zone_id: &str, hostname: &str, tunnel_id: &str) -> Result<String> {
        let v = self.post(
            &format!("/zones/{zone_id}/dns_records"),
            json!({
                "type": "CNAME",
                "proxied": true,
                "name": hostname,
                "content": format!("{tunnel_id}.cfargotunnel.com"),
            }),
        )?;
        Ok(str_field(&v, "id"))
    }

    pub fn delete_dns(&self, zone_id: &str, record_id: &str) -> Result<()> {
        self.delete(&format!("/zones/{zone_id}/dns_records/{record_id}"))?;
        Ok(())
    }

    pub fn delete_tunnel(&self, account: &str, tunnel_id: &str) -> Result<()> {
        self.delete(&format!("/accounts/{account}/cfd_tunnel/{tunnel_id}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------- preflight

#[derive(Debug, Clone)]
pub struct Conflict {
    pub kind: &'static str,
    pub detail: String,
    pub fix: Vec<String>,
}

#[derive(Debug)]
pub struct Preflight {
    pub account: String,
    pub zone: Zone,
    /// Existing DNS records at the hostname (any type).
    pub records: Vec<Record>,
    /// Existing tunnel carrying our name.
    pub tunnel: Option<Tunnel>,
}

impl Preflight {
    pub fn conflicts(&self, hostname: &str, tunnel_name: &str) -> Vec<Conflict> {
        let mut out = Vec::new();
        if !self.records.is_empty() {
            let mut fix = vec![
                format!(
                    "Cloudflare dashboard → https://dash.cloudflare.com/{}/{}/dns/records",
                    self.account, self.zone.name
                ),
                format!("  delete the record named {hostname}"),
            ];
            for r in &self.records {
                fix.push(format!(
                    "API:  DELETE {API}/zones/{}/dns_records/{}   ({}{} → {})",
                    self.zone.id,
                    r.id,
                    r.rtype,
                    if r.proxied { ", proxied" } else { "" },
                    r.content
                ));
            }
            out.push(Conflict {
                kind: "dns",
                detail: format!(
                    "{} already exists in zone {} ({} record)",
                    hostname,
                    self.zone.name,
                    self.records.len()
                ),
                fix,
            });
        }
        if let Some(t) = &self.tunnel {
            out.push(Conflict {
                kind: "tunnel",
                detail: format!(
                    "a tunnel named `{tunnel_name}` already exists (id {}, status {}, {} connection(s))",
                    t.id, t.status, t.connections
                ),
                fix: vec![
                    format!(
                        "Cloudflare dashboard → https://one.dash.cloudflare.com/{}/networks/tunnels",
                        self.account
                    ),
                    format!("  delete the tunnel named {tunnel_name}"),
                    "  if it is still running, stop the connector first: sudo cloudflared service uninstall".to_string(),
                    format!("API:  DELETE {API}/accounts/{}/cfd_tunnel/{}", self.account, t.id),
                ],
            });
        }
        out
    }
}

pub fn preflight(
    cf: &Cf,
    zone_name: &str,
    hostname: &str,
    account_hint: Option<&str>,
    tunnel_name: &str,
) -> Result<Preflight> {
    validate_hostname(hostname, zone_name)?;
    let zone = cf.zone(zone_name)?;
    let account = cf.account(account_hint)?;
    let records = cf.dns_at(&zone.id, hostname)?;
    let tunnel = cf.tunnel_by_name(&account, tunnel_name)?;
    Ok(Preflight { account, zone, records, tunnel })
}

/// Full provisioning. Assumes `preflight` reported no conflicts.
pub fn provision(
    cf: &Cf,
    pf: &Preflight,
    hostname: &str,
    tunnel_name: &str,
    service: &str,
) -> Result<(String, String)> {
    let (tunnel_id, token) = cf.create_tunnel(&pf.account, tunnel_name)?;
    cf.set_ingress(&pf.account, &tunnel_id, hostname, service)?;
    cf.create_cname(&pf.zone.id, hostname, &tunnel_id)?;
    let token = match token {
        Some(t) => t,
        None => cf.tunnel_token(&pf.account, &tunnel_id)?,
    };
    Ok((tunnel_id, token))
}

// ---------------------------------------------------------------- helpers

pub fn validate_hostname(hostname: &str, zone_name: &str) -> Result<()> {
    let h = hostname.trim();
    if h.is_empty() {
        bail!("hostname is empty");
    }
    if h != hostname {
        bail!("hostname `{hostname}` has leading or trailing whitespace");
    }
    if h.contains("://") || h.contains('/') || h.contains(':') {
        bail!("hostname `{h}` must be a bare name like ci.example.com — no scheme, path or port");
    }
    if h.contains('*') {
        bail!("hostname `{h}` must not contain a wildcard");
    }
    if h.to_ascii_lowercase() != h {
        bail!("hostname `{h}` must be lowercase");
    }
    if h.len() > 253 {
        bail!("hostname is longer than 253 characters");
    }
    for label in h.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("hostname `{h}` has an empty or over-long label");
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            bail!("hostname `{h}` may only contain letters, digits, dots and hyphens");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("hostname label `{label}` must not start or end with a hyphen");
        }
    }
    if !h.ends_with(&format!(".{zone_name}")) && h != zone_name {
        bail!("hostname `{h}` is not inside zone `{zone_name}`");
    }
    if h == zone_name {
        bail!(
            "hostname `{h}` is the zone apex; use a subdomain such as ci.{zone_name} — \
             an apex CNAME relies on flattening and is easy to break"
        );
    }
    let depth = h.split('.').count() - zone_name.split('.').count();
    if depth > 1 {
        // Documented Cloudflare constraint: multi-level subdomains need an advanced certificate.
        // Not fatal, but the operator should know before wondering why TLS fails.
        eprintln!(
            "note: `{h}` is a multi-level subdomain; Cloudflare requires an Advanced Certificate \
             for that hostname (see cloudflare-one › common errors)"
        );
    }
    Ok(())
}

fn describe_error(status: u16, value: &Value) -> String {
    let mut msgs: Vec<String> = Vec::new();
    if let Some(errs) = value.get("errors").and_then(Value::as_array) {
        for e in errs {
            let code = e.get("code").and_then(Value::as_i64).unwrap_or(0);
            let msg = e.get("message").and_then(Value::as_str).unwrap_or("").trim();
            if code != 0 && !msg.is_empty() {
                msgs.push(format!("{msg} (code {code})"));
            } else if !msg.is_empty() {
                msgs.push(msg.to_string());
            }
        }
    }
    let detail = if msgs.is_empty() { "no error detail returned".to_string() } else { msgs.join("; ") };

    let hint = match status {
        401 | 403 => Some(
            "the token is rejected. Create it with exactly:\n  \
             Account → Cloudflare Tunnel → Edit\n  \
             Zone → DNS → Edit\n  \
             Zone → Zone → Read",
        ),
        400 if detail.contains("Invalid request headers") => Some(
            "the API token is malformed. Cloudflare tokens are 40 characters; create one at\n               https://dash.cloudflare.com/profile/api-tokens",
        ),
        404 => Some("a resource in the request path does not exist for this token/account"),
        _ => None,
    };

    match hint {
        Some(h) => format!("Cloudflare rejected the request (HTTP {status}): {detail}\n  {h}"),
        None => format!("Cloudflare error (HTTP {status}): {detail}"),
    }
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pf(records: Vec<Record>, tunnel: Option<Tunnel>) -> Preflight {
        Preflight {
            account: "acct123".into(),
            zone: Zone { id: "zone123".into(), name: "example.com".into() },
            records,
            tunnel,
        }
    }

    fn rec(id: &str, t: &str, c: &str) -> Record {
        Record { id: id.into(), rtype: t.into(), content: c.into(), proxied: true }
    }

    #[test]
    fn valid_hostnames_pass() {
        assert!(validate_hostname("ci.example.com", "example.com").is_ok());
        assert!(validate_hostname("deep.ci.example.com", "example.com").is_ok());
    }

    #[test]
    fn hostname_rejects_junk() {
        for bad in [
            "https://ci.example.com",
            "ci.example.com/path",
            "ci.example.com:8443",
            "*.example.com",
            "CI.example.com",
            "",
            "ci..example.com",
            "-ci.example.com",
        ] {
            assert!(validate_hostname(bad, "example.com").is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn hostname_must_be_inside_zone() {
        assert!(validate_hostname("ci.other.org", "example.com").is_err());
        assert!(validate_hostname("ci.example.com.evil.org", "example.com").is_err());
    }

    #[test]
    fn apex_is_refused_with_reason() {
        let err = validate_hostname("example.com", "example.com").unwrap_err().to_string();
        assert!(err.contains("apex"), "{err}");
    }

    #[test]
    fn existing_dns_is_a_conflict_with_delete_instructions() {
        let p = pf(vec![rec("r1", "A", "1.2.3.4"), rec("r2", "CNAME", "old.example.net")], None);
        let c = p.conflicts("ci.example.com", "selfhost-ci-cd");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].kind, "dns");
        let fix = c[0].fix.join("\n");
        assert!(fix.contains("dash.cloudflare.com/acct123/example.com/dns/records"), "{fix}");
        assert!(fix.contains("dns_records/r1"), "{fix}");
        assert!(fix.contains("dns_records/r2"), "{fix}");
        assert!(fix.contains("delete the record named ci.example.com"), "{fix}");
    }

    #[test]
    fn existing_tunnel_is_a_conflict_with_stop_and_delete_instructions() {
        let p = pf(
            vec![],
            Some(Tunnel {
                id: "t1".into(),
                name: "selfhost-ci-cd".into(),
                status: "healthy".into(),
                connections: 2,
            }),
        );
        let c = p.conflicts("ci.example.com", "selfhost-ci-cd");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].kind, "tunnel");
        assert!(c[0].detail.contains("2 connection(s)"), "{}", c[0].detail);
        let fix = c[0].fix.join("\n");
        assert!(fix.contains("networks/tunnels"), "{fix}");
        assert!(fix.contains("cfd_tunnel/t1"), "{fix}");
        assert!(fix.contains("service uninstall"), "{fix}");
    }

    #[test]
    fn both_conflicts_are_reported_together() {
        let p = pf(
            vec![rec("r1", "A", "1.2.3.4")],
            Some(Tunnel { id: "t1".into(), name: "selfhost-ci-cd".into(), status: "inactive".into(), connections: 0 }),
        );
        let kinds: Vec<_> = p.conflicts("ci.example.com", "selfhost-ci-cd").iter().map(|c| c.kind).collect();
        assert_eq!(kinds, vec!["dns", "tunnel"]);
    }

    #[test]
    fn clean_preflight_has_no_conflicts() {
        assert!(pf(vec![], None).conflicts("ci.example.com", "selfhost-ci-cd").is_empty());
    }

    #[test]
    fn http_403_names_the_permissions() {
        let v: Value = serde_json::from_str(
            r#"{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}"#,
        )
        .unwrap();
        let msg = describe_error(403, &v);
        assert!(msg.contains("Authentication error"), "{msg}");
        assert!(msg.contains("Cloudflare Tunnel → Edit"), "{msg}");
        assert!(msg.contains("code 10000"), "{msg}");
    }

    #[test]
    fn query_encoding_is_safe() {
        assert_eq!(enc("ci.example.com"), "ci.example.com");
        assert_eq!(enc("a b&c"), "a%20b%26c");
    }
}
