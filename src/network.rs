//! What on this machine accepts network connections.
//!
//! Read from the operating system through the `listeners` crate: TCP sockets
//! in the LISTEN state, with the process that owns each one. Without
//! administrator rights the OS only reveals processes running as the current
//! user, which is where development servers, databases and container runtimes
//! run; system services owned by root are left out.

use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::{Result, anyhow};
use serde::Serialize;

/// One program listening on one TCP port, on one or more addresses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Listening {
    /// The process name, as the OS reports it (`node`, `com.docker.backend`).
    pub process: String,
    /// The executable, when the OS reveals it.
    pub path: String,
    /// Every process of that name listening on the port (pre-forked servers have several).
    pub pids: Vec<u32>,
    pub port: u16,
    /// Each address the port is bound to, sorted.
    pub addresses: Vec<IpAddr>,
}

/// Who can connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Reach {
    /// Loopback only: programs on this machine.
    Local,
    /// Some address other than loopback: other devices on the network too.
    Network,
}

pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        // `::ffff:127.0.0.1` and the old `::127.0.0.1` form are loopback too.
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
    }
}

impl Listening {
    pub fn reach(&self) -> Reach {
        if self.addresses.iter().all(|a| is_loopback(*a)) {
            Reach::Local
        } else {
            Reach::Network
        }
    }

    /// Bound to `0.0.0.0` or `::`: every interface, present and future.
    pub fn all_interfaces(&self) -> bool {
        self.addresses.iter().any(IpAddr::is_unspecified)
    }

    /// `0.0.0.0:5432, [::]:5432`.
    pub fn sockets(&self) -> String {
        self.addresses
            .iter()
            .map(|a| match a {
                IpAddr::V4(v4) => format!("{v4}:{}", self.port),
                IpAddr::V6(v6) => format!("[{v6}]:{}", self.port),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `node (pid 4242)`.
    pub fn who(&self) -> String {
        let pids: Vec<String> = self.pids.iter().map(u32::to_string).collect();
        let label = if pids.len() == 1 { "pid" } else { "pids" };
        format!("{} ({label} {})", self.process, pids.join(", "))
    }
}

/// Group raw `(process, path, pid, address, port)` sockets by program and port.
pub fn group(
    sockets: impl IntoIterator<Item = (String, String, u32, IpAddr, u16)>,
) -> Vec<Listening> {
    let mut map: BTreeMap<(String, u16), Listening> = BTreeMap::new();
    for (process, path, pid, address, port) in sockets {
        let entry = map
            .entry((process.clone(), port))
            .or_insert_with(|| Listening {
                process,
                path: String::new(),
                pids: Vec::new(),
                port,
                addresses: Vec::new(),
            });
        if entry.path.is_empty() {
            entry.path = path;
        }
        if !entry.pids.contains(&pid) {
            entry.pids.push(pid);
        }
        if !entry.addresses.contains(&address) {
            entry.addresses.push(address);
        }
    }
    let mut out: Vec<Listening> = map.into_values().collect();
    for l in &mut out {
        l.pids.sort_unstable();
        l.addresses.sort();
    }
    out
}

/// Every TCP port a program running as this user is listening on, by program
/// name, then port.
pub fn listening() -> Result<Vec<Listening>> {
    if !listeners::IS_OS_SUPPORTED {
        return Ok(Vec::new());
    }
    let all = listeners::get_all().map_err(|e| anyhow!("cannot list listening sockets: {e}"))?;
    Ok(group(
        all.into_iter()
            .filter(|l| l.protocol == listeners::Protocol::TCP)
            .filter(|l| l.state == listeners::SocketState::Listen)
            .map(|l| {
                (
                    l.process.name,
                    l.process.path,
                    l.process.pid,
                    l.socket.ip(),
                    l.socket.port(),
                )
            }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_includes_mapped_forms() {
        assert!(is_loopback(ip("127.0.0.1")));
        assert!(is_loopback(ip("127.1.2.3")));
        assert!(is_loopback(ip("::1")));
        assert!(is_loopback(ip("::ffff:127.0.0.1")));
        assert!(is_loopback(ip("::7f00:1")));
        assert!(!is_loopback(ip("0.0.0.0")));
        assert!(!is_loopback(ip("::")));
        assert!(!is_loopback(ip("192.168.1.10")));
    }

    #[test]
    fn groups_by_program_and_port() {
        let s = |name: &str, pid, addr: &str, port| {
            (
                name.to_string(),
                format!("/bin/{name}"),
                pid,
                ip(addr),
                port,
            )
        };
        let out = group([
            s("postgres", 10, "0.0.0.0", 5432),
            s("postgres", 10, "::", 5432),
            s("postgres", 11, "0.0.0.0", 5432),
            s("node", 20, "127.0.0.1", 3000),
            s("node", 20, "127.0.0.1", 3000),
        ]);
        assert_eq!(out.len(), 2);
        let node = &out[0];
        assert_eq!((node.process.as_str(), node.port), ("node", 3000));
        assert_eq!(node.reach(), Reach::Local);
        assert_eq!(node.sockets(), "127.0.0.1:3000");
        let pg = &out[1];
        assert_eq!(pg.pids, vec![10, 11]);
        assert_eq!(pg.reach(), Reach::Network);
        assert!(pg.all_interfaces());
        assert_eq!(pg.sockets(), "0.0.0.0:5432, [::]:5432");
        assert_eq!(pg.who(), "postgres (pids 10, 11)");
    }

    #[test]
    fn one_lan_address_is_network_but_not_all_interfaces() {
        let out = group([("vite".into(), String::new(), 1, ip("192.168.1.5"), 5173)]);
        assert_eq!(out[0].reach(), Reach::Network);
        assert!(!out[0].all_interfaces());
    }
}
