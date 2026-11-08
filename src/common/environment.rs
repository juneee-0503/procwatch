//! Where procwatch is running. Figures mean different things in a container,
//! so this is found out at start and shown.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Environment {
    pub container: Option<String>,
    pub wsl: bool,
    pub virtual_machine: Option<String>,
    pub privileged: bool,
}

/// Which container runtime a cgroup file shows, if any.
pub fn container_in(cgroup: &str) -> Option<&'static str> {
    [("docker", "docker"), ("kubepods", "kubernetes"), ("containerd", "containerd"), ("lxc", "lxc"), ("podman", "podman"), ("libpod", "podman")].iter().find(|(needle, _)| cgroup.contains(needle)).map(|(_, name)| *name)
}

pub fn privileged() -> bool {
    #[cfg(unix)]
    return unsafe { libc::geteuid() == 0 };
    #[cfg(windows)]
    return crate::common::command::tool("net").arg("session").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success());
}

pub fn detect() -> Environment {
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let cgroup = read("/proc/1/cgroup");
    let mut container = container_in(&cgroup).map(str::to_string);
    if container.is_none() && std::path::Path::new("/.dockerenv").exists() {
        container = Some("docker".to_string());
    }
    if container.is_none() && std::path::Path::new("/run/.containerenv").exists() {
        container = Some("podman".to_string());
    }
    let version = read("/proc/version").to_lowercase();
    let vendor = read("/sys/class/dmi/id/sys_vendor").to_lowercase();
    let virtual_machine = ["kvm", "qemu", "vmware", "virtualbox", "xen", "microsoft corporation", "amazon ec2", "google"].iter().find(|v| vendor.contains(**v)).map(|v| (*v).to_string());
    Environment { container, wsl: version.contains("microsoft"), virtual_machine, privileged: privileged() }
}

impl Environment {
    /// What changes about the figures here.
    pub fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(c) = &self.container {
            out.push(format!("in a {c} container: /proc may show the host, and CPU and memory limits may be lower than these figures suggest"));
        }
        if self.wsl {
            out.push("under WSL: disks, sensors and services are those of a virtual machine".to_string());
        }
        if self.virtual_machine.is_some() {
            out.push("in a virtual machine: temperature and power are rarely available".to_string());
        }
        if !self.privileged {
            out.push("not privileged: some sources will be limited, each says which".to_string());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_containers() {
        assert_eq!(container_in("0::/docker/abc123"), Some("docker"));
        assert_eq!(container_in("12:cpu:/kubepods/burstable/pod1"), Some("kubernetes"));
        assert_eq!(container_in("0::/init.scope"), None);
    }

    #[test]
    fn explains_what_differs() {
        let e = Environment { container: Some("docker".into()), wsl: true, virtual_machine: None, privileged: true };
        assert_eq!(e.notes().len(), 2);
    }
}
