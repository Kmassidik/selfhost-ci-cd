//! Platform probe (PRD D17 / §6.1).
//!
//! OS and CPU are independent failure axes, so they are probed independently and never
//! inferred from each other. Linux is complete; macOS and Windows report what they can and
//! name the fields they cannot read in `unavailable` rather than inventing values.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub pointer_width: u8,
    pub cpu_vendor: Option<String>,
    pub cpu_model: Option<String>,
    pub x86_level: Option<String>,
    pub cpu_flags: Vec<String>,
    pub page_size: Option<u64>,
    pub ram_bytes: Option<u64>,
    pub disk_bytes: Option<u64>,
    pub kvm: Option<bool>,
    pub virt_flags: Vec<String>,
    pub tpm: Option<bool>,
    pub init_system: Option<String>,
    pub captured_at: u64,
    pub unavailable: Vec<String>,
}

impl Probe {
    pub fn detect() -> Self {
        let mut unavailable = Vec::new();

        let (cpu_vendor, cpu_model, flags) = cpu_info(&mut unavailable);
        let flag_set: BTreeSet<String> = flags.iter().cloned().collect();

        let arch = uname_machine()
            .or_else(|| Some(std::env::consts::ARCH.to_string()))
            .unwrap_or_else(|| "unknown".into());

        let p = Probe {
            os: std::env::consts::OS.to_string(),
            os_version: os_version(&mut unavailable),
            x86_level: x86_level(&arch, &flag_set),
            arch,
            pointer_width: (std::mem::size_of::<usize>() * 8) as u8,
            cpu_vendor,
            cpu_model,
            cpu_flags: flags,
            page_size: page_size(&mut unavailable),
            ram_bytes: ram_bytes(&mut unavailable),
            disk_bytes: disk_bytes(&mut unavailable),
            kvm: kvm(&mut unavailable),
            virt_flags: virt_flags(&flag_set, &mut unavailable),
            tpm: tpm(&mut unavailable),
            init_system: init_system(&mut unavailable),
            captured_at: now(),
            unavailable,
        };
        p
    }

    /// Lowest baseline this host satisfies. Used to gate artifact and pack selection.
    pub fn baseline(&self) -> String {
        match self.arch.as_str() {
            "x86_64" | "amd64" => format!("x86_64-{}", self.x86_level.as_deref().unwrap_or("v1")),
            "aarch64" | "arm64" => "aarch64-v8.0".to_string(),
            other => other.to_string(),
        }
    }

    pub fn ram_gib(&self) -> Option<f64> {
        self.ram_bytes.map(|b| b as f64 / 1024.0 / 1024.0 / 1024.0)
    }

    pub fn disk_gib(&self) -> Option<f64> {
        self.disk_bytes.map(|b| b as f64 / 1024.0 / 1024.0 / 1024.0)
    }
}

impl std::fmt::Display for Probe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "os            {} {}", self.os, self.os_version)?;
        writeln!(f, "arch          {} ({} bit)", self.arch, self.pointer_width)?;
        writeln!(f, "baseline      {}", self.baseline())?;
        if let (Some(v), Some(m)) = (&self.cpu_vendor, &self.cpu_model) {
            writeln!(f, "cpu           {v} {m}")?;
        }
        if let Some(l) = &self.x86_level {
            writeln!(f, "x86-64 level  {l}")?;
        }
        writeln!(f, "page size     {}", self.page_size.map(|v| v.to_string()).unwrap_or_else(|| "?".into()))?;
        writeln!(f, "ram           {}", self.ram_gib().map(|v| format!("{v:.1} GiB")).unwrap_or_else(|| "?".into()))?;
        writeln!(f, "disk /        {}", self.disk_gib().map(|v| format!("{v:.0} GiB")).unwrap_or_else(|| "?".into()))?;
        writeln!(f, "kvm           {}", opt_bool(self.kvm))?;
        writeln!(f, "virtualisation {}", if self.virt_flags.is_empty() { "-".to_string() } else { self.virt_flags.join(", ") })?;
        writeln!(f, "tpm           {}", opt_bool(self.tpm))?;
        writeln!(f, "init          {}", self.init_system.as_deref().unwrap_or("?"))?;
        if !self.unavailable.is_empty() {
            writeln!(f, "unavailable   {}", self.unavailable.join(", "))?;
        }
        Ok(())
    }
}

fn opt_bool(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "yes",
        Some(false) => "no",
        None => "?",
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------- uname

#[cfg(unix)]
fn uname_machine() -> Option<String> {
    use std::ffi::CStr;
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return None;
    }
    let c = unsafe { CStr::from_ptr(u.machine.as_ptr()) };
    Some(c.to_string_lossy().into_owned())
}

#[cfg(not(unix))]
fn uname_machine() -> Option<String> {
    None
}

// ---------------------------------------------------------------- os

#[cfg(target_os = "linux")]
fn os_version(unavailable: &mut Vec<String>) -> String {
    let text = match std::fs::read_to_string("/etc/os-release") {
        Ok(t) => t,
        Err(_) => {
            unavailable.push("os_version".into());
            return "unknown".into();
        }
    };
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .map(|v| v.trim_matches('"').to_string())
    };
    let name = field("PRETTY_NAME").or_else(|| field("NAME")).unwrap_or_else(|| "linux".into());
    name
}

#[cfg(not(target_os = "linux"))]
fn os_version(unavailable: &mut Vec<String>) -> String {
    unavailable.push("os_version".into());
    "unknown".into()
}

// ---------------------------------------------------------------- cpu

#[cfg(target_os = "linux")]
fn cpu_info(unavailable: &mut Vec<String>) -> (Option<String>, Option<String>, Vec<String>) {
    let text = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(t) => t,
        Err(_) => {
            unavailable.push("cpu_info".into());
            return (None, None, Vec::new());
        }
    };
    let mut vendor = None;
    let mut model = None;
    let mut flags: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            match k {
                "vendor_id" => vendor.get_or_insert_with(|| v.to_string()),
                "model name" | "Hardware" | "Processor" => model.get_or_insert_with(|| v.to_string()),
                "flags" | "Features" => {
                    for f in v.split_whitespace() {
                        flags.insert(f.to_string());
                    }
                    continue;
                }
                _ => continue,
            };
        }
    }
    (vendor, model, flags.into_iter().collect())
}

#[cfg(not(target_os = "linux"))]
fn cpu_info(unavailable: &mut Vec<String>) -> (Option<String>, Option<String>, Vec<String>) {
    unavailable.push("cpu_info".into());
    (None, None, Vec::new())
}

fn x86_level(arch: &str, flags: &BTreeSet<String>) -> Option<String> {
    if arch != "x86_64" && arch != "amd64" {
        return None;
    }
    // Linux exposes SSE3 as `pni`; accept either spelling. Older kernels also report
    // ABM as `lzcnt`.
    let has = |f: &str| match f {
        "sse3" => flags.contains("sse3") || flags.contains("pni"),
        "abm" => flags.contains("abm") || flags.contains("lzcnt"),
        _ => flags.contains(f),
    };
    let v2 = ["cx16", "lahf_lm", "popcnt", "sse3", "sse4_1", "sse4_2", "ssse3"];
    let v3 = ["avx", "avx2", "bmi1", "bmi2", "fma", "movbe", "abm", "xsave"];
    let v4 = ["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"];

    if v4.iter().all(|f| has(f)) {
        Some("v4".into())
    } else if v2.iter().chain(v3.iter()).all(|f| has(f)) {
        Some("v3".into())
    } else if v2.iter().all(|f| has(f)) {
        Some("v2".into())
    } else {
        // Baseline x86-64 (v1). SSE2 is mandatory in the ABI.
        Some("v1".into())
    }
}

// ---------------------------------------------------------------- memory / disk

#[cfg(target_os = "linux")]
fn ram_bytes(_unavailable: &mut Vec<String>) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

#[cfg(not(target_os = "linux"))]
fn ram_bytes(unavailable: &mut Vec<String>) -> Option<u64> {
    unavailable.push("ram_bytes".into());
    None
}

#[cfg(unix)]
fn disk_bytes(unavailable: &mut Vec<String>) -> Option<u64> {
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let path = std::ffi::CString::new("/").ok()?;
    if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
        unavailable.push("disk_bytes".into());
        return None;
    }
    Some(st.f_blocks as u64 * st.f_frsize as u64)
}

#[cfg(not(unix))]
fn disk_bytes(unavailable: &mut Vec<String>) -> Option<u64> {
    unavailable.push("disk_bytes".into());
    None
}

// ---------------------------------------------------------------- page size / init / virt

#[cfg(unix)]
fn page_size(unavailable: &mut Vec<String>) -> Option<u64> {
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 { Some(v as u64) } else { unavailable.push("page_size".into()); None }
}

#[cfg(not(unix))]
fn page_size(unavailable: &mut Vec<String>) -> Option<u64> {
    unavailable.push("page_size".into());
    None
}

#[cfg(target_os = "linux")]
fn init_system(_unavailable: &mut Vec<String>) -> Option<String> {
    if std::path::Path::new("/run/systemd/system").is_dir() {
        Some("systemd".into())
    } else {
        Some("other".into())
    }
}

#[cfg(target_os = "macos")]
fn init_system(_unavailable: &mut Vec<String>) -> Option<String> {
    Some("launchd".into())
}

#[cfg(windows)]
fn init_system(_unavailable: &mut Vec<String>) -> Option<String> {
    Some("scm".into())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn init_system(unavailable: &mut Vec<String>) -> Option<String> {
    unavailable.push("init_system".into());
    None
}

#[cfg(target_os = "linux")]
fn kvm(_unavailable: &mut Vec<String>) -> Option<bool> {
    Some(std::path::Path::new("/dev/kvm").exists())
}

#[cfg(not(target_os = "linux"))]
fn kvm(unavailable: &mut Vec<String>) -> Option<bool> {
    unavailable.push("kvm".into());
    None
}

#[cfg(target_os = "linux")]
fn tpm(_unavailable: &mut Vec<String>) -> Option<bool> {
    Some(
        std::path::Path::new("/dev/tpm0").exists()
            || std::path::Path::new("/sys/class/tpm/tpm0").exists(),
    )
}

#[cfg(not(target_os = "linux"))]
fn tpm(unavailable: &mut Vec<String>) -> Option<bool> {
    unavailable.push("tpm".into());
    None
}

#[cfg(target_os = "linux")]
fn virt_flags(flags: &BTreeSet<String>, _unavailable: &mut Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    if flags.contains("vmx") {
        out.push("vt-x".into());
    }
    if flags.contains("svm") {
        out.push("amd-v".into());
    }
    for (module, label) in [("kvm_intel", "nested-kvm-intel"), ("kvm_amd", "nested-kvm-amd")] {
        let path = format!("/sys/module/{module}/parameters/nested");
        if let Ok(v) = std::fs::read_to_string(&path) {
            let v = v.trim();
            if v == "1" || v == "Y" || v == "y" {
                out.push(label.into());
            }
        }
    }
    if std::path::Path::new("/dev/kvm").exists() {
        out.push("kvm".into());
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn virt_flags(_flags: &BTreeSet<String>, unavailable: &mut Vec<String>) -> Vec<String> {
    unavailable.push("virt_flags".into());
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn x86_level_is_monotonic() {
        let v2 = flags(&["cx16", "lahf_lm", "popcnt", "sse3", "sse4_1", "sse4_2", "ssse3"]);
        assert_eq!(x86_level("x86_64", &v2).as_deref(), Some("v2"));

        let mut v3 = v2.clone();
        for f in ["avx", "avx2", "bmi1", "bmi2", "fma", "movbe", "abm", "xsave"] {
            v3.insert(f.into());
        }
        assert_eq!(x86_level("x86_64", &v3).as_deref(), Some("v3"));

        let mut v4 = v3.clone();
        for f in ["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"] {
            v4.insert(f.into());
        }
        assert_eq!(x86_level("x86_64", &v4).as_deref(), Some("v4"));
    }

    #[test]
    fn sse3_is_recognised_as_pni() {
        // Linux reports SSE3 as `pni`; a host with only that spelling is still v2.
        let f = flags(&["cx16", "lahf_lm", "popcnt", "pni", "sse4_1", "sse4_2", "ssse3"]);
        assert_eq!(x86_level("x86_64", &f).as_deref(), Some("v2"));
    }

    #[test]
    fn x86_level_ignores_non_x86() {
        let f = flags(&["cx16", "lahf_lm", "popcnt", "sse3", "sse4_1", "sse4_2", "ssse3"]);
        assert_eq!(x86_level("aarch64", &f), None);
    }

    #[test]
    fn baseline_matches_arch() {
        let mut p = Probe {
            os: "linux".into(), os_version: "x".into(), arch: "x86_64".into(), pointer_width: 64,
            cpu_vendor: None, cpu_model: None, x86_level: Some("v2".into()), cpu_flags: vec![],
            page_size: Some(4096), ram_bytes: None, disk_bytes: None, kvm: None,
            virt_flags: vec![], tpm: None, init_system: None, captured_at: 0,
            unavailable: vec![],
        };
        assert_eq!(p.baseline(), "x86_64-v2");
        p.arch = "aarch64".into();
        p.x86_level = None;
        assert_eq!(p.baseline(), "aarch64-v8.0");
    }
}
