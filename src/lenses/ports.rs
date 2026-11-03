//! Programs that accept connections from the network.
//!
//! A development machine moves between office, home, café and conference
//! Wi-Fi, and every device on those networks can connect to whatever listens
//! on an address other than loopback. Development servers started with
//! `--host`, debuggers, databases without a password and container ports
//! published on `0.0.0.0` are all reachable that way, often without the user
//! knowing. This lens lists what is listening ([`crate::network`]) and reports
//! what other devices can reach:
//!
//! - **Known services** (debuggers, the Docker API, databases, Jupyter): one
//!   finding per port, critical to medium, with that service's own remedy.
//! - **Container runtimes and development servers**: one medium finding per
//!   program, listing its ports.
//! - **Anything else**: one informational finding per program, not alerted.
//!
//! What only this machine can reach is listed as passing.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::Result;
use lenstica_lens::{
    Category, Context, Finding, Lens, Location, Report, Severity, key_part, topic,
};
use serde_json::Value;

use crate::network::{self, Listening, Reach};

pub const ID: &str = "listening-ports";
const CATEGORY: Category = Category::Network;

pub struct ListeningPorts;

struct Service {
    name: &'static str,
    severity: Severity,
    ports: &'static [u16],
    /// Process names (lowercase) that identify it on any port.
    processes: &'static [&'static str],
    /// The port alone is too common: the process must match as well.
    port_needs_process: bool,
    why: &'static str,
    remedy: &'static str,
}

const NO_PASSWORD: &str = "Development databases often have no password, or a well-known one, so whoever connects can read and change the data.";

/// Most specific first: a Node.js process on 9229 is the inspector, not a dev server.
const SERVICES: &[Service] = &[
    Service {
        name: "Node.js inspector",
        severity: Severity::Critical,
        ports: &[9229],
        processes: &[],
        port_needs_process: false,
        why: "Whoever connects to the inspector can run any code as you.",
        remedy: "Start Node.js with `--inspect` or `--inspect=127.0.0.1:9229` (localhost is the default), never `--inspect=0.0.0.0`, and stop the debugger when you are done.",
    },
    Service {
        name: "Chrome remote debugging",
        severity: Severity::Critical,
        ports: &[9222],
        processes: &[],
        port_needs_process: false,
        why: "Whoever connects controls the browser: they can read its cookies and run code in any page you are signed in to.",
        remedy: "Quit the browser started with `--remote-debugging-port`, or start it so it listens on 127.0.0.1 only.",
    },
    Service {
        name: "Python debugger (debugpy)",
        severity: Severity::Critical,
        ports: &[5678],
        processes: &[],
        port_needs_process: false,
        why: "Whoever connects to the debugger can run any Python code as you.",
        remedy: "Start debugpy with `--listen 127.0.0.1:5678`.",
    },
    Service {
        name: "Java debugger (JDWP)",
        severity: Severity::Critical,
        ports: &[5005],
        processes: &["java"],
        port_needs_process: true,
        why: "Whoever connects to the debug port can run any Java code as you.",
        remedy: "Use `address=127.0.0.1:5005` in `-agentlib:jdwp=…`.",
    },
    Service {
        name: "Docker Engine API",
        severity: Severity::Critical,
        ports: &[2375],
        processes: &[],
        port_needs_process: false,
        why: "The Docker API without TLS gives whoever connects full control of Docker, which amounts to administrator access to this machine.",
        remedy: "Remove the `tcp://` entry from dockerd's `hosts` (daemon.json or `-H`), or require TLS on port 2376.",
    },
    Service {
        name: "PostgreSQL",
        severity: Severity::High,
        ports: &[5432],
        processes: &["postgres", "postmaster"],
        port_needs_process: false,
        why: NO_PASSWORD,
        remedy: "Set `listen_addresses = 'localhost'` in postgresql.conf and restart PostgreSQL.",
    },
    Service {
        name: "MySQL",
        severity: Severity::High,
        ports: &[3306],
        processes: &["mysqld", "mariadbd"],
        port_needs_process: false,
        why: NO_PASSWORD,
        remedy: "Set `bind-address = 127.0.0.1` under `[mysqld]` in my.cnf and restart it.",
    },
    Service {
        name: "MongoDB",
        severity: Severity::High,
        ports: &[27017],
        processes: &["mongod"],
        port_needs_process: false,
        why: NO_PASSWORD,
        remedy: "Set `net.bindIp: 127.0.0.1` in mongod.conf and restart it.",
    },
    Service {
        name: "Redis",
        severity: Severity::High,
        ports: &[6379],
        processes: &["redis-server", "valkey-server"],
        port_needs_process: false,
        why: NO_PASSWORD,
        remedy: "Set `bind 127.0.0.1 -::1` and `protected-mode yes` in redis.conf and restart it.",
    },
    Service {
        name: "Memcached",
        severity: Severity::High,
        ports: &[11211],
        processes: &["memcached"],
        port_needs_process: false,
        why: "Memcached has no password: whoever connects can read and change everything cached.",
        remedy: "Start memcached with `-l 127.0.0.1`.",
    },
    Service {
        name: "Elasticsearch or OpenSearch",
        severity: Severity::High,
        ports: &[9200, 9300],
        processes: &[],
        port_needs_process: false,
        why: NO_PASSWORD,
        remedy: "Set `network.host: 127.0.0.1` in elasticsearch.yml (opensearch.yml) and restart it.",
    },
    Service {
        name: "ClickHouse",
        severity: Severity::High,
        ports: &[8123],
        processes: &["clickhouse", "clickhouse-server"],
        port_needs_process: false,
        why: NO_PASSWORD,
        remedy: "Set `<listen_host>127.0.0.1</listen_host>` in the ClickHouse config and restart it.",
    },
    Service {
        name: "a database or message broker",
        severity: Severity::High,
        // CouchDB, Cassandra, Neo4j, RabbitMQ, Kafka, SQL Server, etcd, CockroachDB, InfluxDB.
        ports: &[
            5984, 9042, 7474, 7687, 5672, 15672, 9092, 1433, 2379, 26257, 8086,
        ],
        processes: &["couchdb", "sqlservr", "etcd", "cockroach", "influxd"],
        port_needs_process: false,
        why: NO_PASSWORD,
        remedy: "Configure it to listen on 127.0.0.1 only.",
    },
    Service {
        name: "Jupyter",
        severity: Severity::Medium,
        ports: &[8888],
        processes: &[],
        port_needs_process: false,
        why: "Jupyter runs whatever code it is sent. It asks for a token by default, unless that was turned off.",
        remedy: "Start it without `--ip=0.0.0.0`; it listens on localhost by default.",
    },
];

/// Programs that publish container ports on the host (lowercase), and the
/// product they belong to.
const CONTAINER_RUNTIMES: &[(&str, &str)] = &[
    ("com.docker.backend", "Docker"),
    ("com.docker.vpnkit", "Docker"),
    ("vpnkit-bridge", "Docker"),
    ("docker-proxy", "Docker"),
    ("dockerd", "Docker"),
    ("orbstack helper", "OrbStack"),
    ("gvproxy", "Podman"),
    ("limactl", "Lima"),
];

/// The container runtime a process belongs to, by product name.
fn container_runtime(process: &str) -> Option<&'static str> {
    let process = process.to_ascii_lowercase();
    CONTAINER_RUNTIMES
        .iter()
        .find(|(name, _)| *name == process)
        .map(|(_, product)| *product)
}

/// Interpreters and runtimes that development servers run on.
fn is_dev_runtime(process: &str) -> bool {
    matches!(
        process,
        "node"
            | "nodejs"
            | "deno"
            | "bun"
            | "ruby"
            | "php"
            | "java"
            | "dotnet"
            | "beam.smp"
            | "uvicorn"
            | "gunicorn"
    ) || process.starts_with("python")
}

enum Kind {
    Service(&'static Service),
    Container,
    DevServer,
    Other,
}

fn classify(l: &Listening) -> Kind {
    let process = l.process.to_ascii_lowercase();
    let port_matches = |s: &Service| s.ports.contains(&l.port);
    let process_matches = |s: &Service| s.processes.contains(&process.as_str());
    let container = container_runtime(&process).is_some();
    let service = SERVICES.iter().find(|s| {
        if s.port_needs_process {
            port_matches(s) && process_matches(s)
        } else {
            // A container runtime is only a service through the port it publishes.
            port_matches(s) || (!container && process_matches(s))
        }
    });
    match service {
        Some(s) => Kind::Service(s),
        None if container => Kind::Container,
        None if is_dev_runtime(&process) => Kind::DevServer,
        None => Kind::Other,
    }
}

/// The key of the finding that covers this listener, when other devices can
/// reach it: known services per port, everything else per program.
pub fn finding_key(l: &Listening) -> Option<String> {
    if l.reach() == Reach::Local {
        return None;
    }
    Some(match classify(l) {
        Kind::Service(_) => format!("listen|{}|{}", key_part(&l.process), l.port),
        _ => format!("listen|{}", key_part(&l.process)),
    })
}

/// `[lenses.listening-ports] ignore`: `"5432"` (a port), `"node"` (a program,
/// any case) or `"node:3000"` (a program on one port).
struct Ignore(Vec<String>);

impl Ignore {
    fn from_settings(settings: &Value) -> Self {
        Ignore(
            settings
                .get("ignore")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(|s| s.trim().to_ascii_lowercase())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        )
    }

    fn skips(&self, l: &Listening) -> bool {
        // The name as shown, or as spelled in finding keys (`OrbStack_Helper`).
        let names = [
            l.process.to_ascii_lowercase(),
            key_part(&l.process).to_ascii_lowercase(),
        ];
        let port = l.port.to_string();
        self.0.iter().any(|e| {
            *e == port
                || names.iter().any(|n| {
                    e == n
                        || e.strip_suffix(port.as_str())
                            .and_then(|r| r.strip_suffix(':'))
                            == Some(n)
                })
        })
    }
}

const REACHABLE: &str = "Other devices on the same network (an office, café, hotel or conference Wi-Fi) can connect to it, unless a firewall blocks them.";

/// Explains `0.0.0.0` and `::` when any of these listeners uses them.
fn every_interface_note(group: &[&Listening]) -> &'static str {
    if group.iter().any(|l| l.all_interfaces()) {
        " `0.0.0.0` and `::` mean every network interface: Wi-Fi, Ethernet and any VPN."
    } else {
        ""
    }
}

fn location(l: &Listening) -> Location {
    // No `path`: the window offers to open a location, and opening an
    // executable would run it.
    Location::label(format!("{} on {}", l.who(), l.sockets()))
}

fn executable(l: &Listening) -> String {
    if l.path.is_empty() {
        String::new()
    } else {
        format!("\nProgram: {}", l.path)
    }
}

fn docker_remedy(ports: &[u16]) -> String {
    let example = ports.first().copied().unwrap_or(8080);
    format!(
        "Publish container ports on localhost only: `\"127.0.0.1:{example}:…\"` instead of `\"{example}:…\"` under `ports:` in compose, or `docker run -p 127.0.0.1:{example}:…`. \
         To make localhost the default for every container, set `\"ip\": \"127.0.0.1\"` in Docker's daemon.json (Docker Desktop: Settings → Docker Engine)."
    )
}

const DEV_REMEDY: &str = "Unless you need to open it from another device, bind the server to 127.0.0.1: drop `--host` (Vite, Astro, Nuxt), use `-H 127.0.0.1` (Next.js), `--host 127.0.0.1` (uvicorn, Flask), `runserver 127.0.0.1:8000` (Django), `-b 127.0.0.1` (Rails), or pass `127.0.0.1` as the host to `listen()`.";

const OTHER_REMEDY: &str = "Nothing to do if you use this app's network features (sharing, casting, syncing, remote control). If you don't, turn them off in the app, or block incoming connections to it with the firewall.";

fn service_finding(l: &Listening, s: &Service) -> Finding {
    let runtime = container_runtime(&l.process);
    let (who, remedy) = match runtime {
        Some(product) => (
            format!(
                "{product} publishes a container's port {}, the usual port of {}, through {}. It accepts",
                l.port,
                s.name,
                l.who()
            ),
            docker_remedy(&[l.port]),
        ),
        None => (format!("{} accepts", l.who()), s.remedy.to_string()),
    };
    Finding::new(
        finding_key(l).unwrap_or_default(),
        s.severity,
        CATEGORY,
        format!(
            "{} (port {}) is reachable from your network",
            capitalise(s.name),
            l.port
        ),
    )
    .detail(format!(
        "{who} connections on {}. {REACHABLE}{}\n{}{}",
        l.sockets(),
        every_interface_note(&[l]),
        s.why,
        executable(l)
    ))
    .topic(topic::OPEN_PORTS)
    .remedy(remedy)
    .at(location(l))
}

fn ports_list(ports: &[u16]) -> String {
    let list: Vec<String> = ports.iter().map(u16::to_string).collect();
    list.join(", ")
}

/// One finding for every port of a program that isn't a known service.
fn program_finding(kind: &Kind, group: &[&Listening]) -> Finding {
    let first = group[0];
    let ports: Vec<u16> = group.iter().map(|l| l.port).collect();
    let n = ports.len();
    let port_words = if n == 1 {
        format!("port {}", ports[0])
    } else {
        format!("ports {}", ports_list(&ports))
    };
    let (severity, title, why, remedy) = match kind {
        Kind::Container => (
            Severity::Medium,
            format!(
                "{} publishes {} to your network",
                container_runtime(&first.process).unwrap_or("A container runtime"),
                if n == 1 {
                    format!("container port {}", ports[0])
                } else {
                    format!("{n} container ports")
                }
            ),
            "A container port published without an address is bound to every interface.",
            docker_remedy(&ports),
        ),
        Kind::DevServer => (
            Severity::Medium,
            format!(
                "{} accepts connections from your network on {port_words}",
                first.process
            ),
            "Development servers often serve source code, debug pages and unauthenticated APIs.",
            DEV_REMEDY.to_string(),
        ),
        _ => (
            Severity::Info,
            format!(
                "{} accepts connections from your network on {port_words}",
                first.process
            ),
            "",
            OTHER_REMEDY.to_string(),
        ),
    };
    let sockets: Vec<String> = group.iter().map(|l| format!("  {}", l.sockets())).collect();
    let mut detail = format!("{REACHABLE}{}", every_interface_note(group));
    if !why.is_empty() {
        detail.push(' ');
        detail.push_str(why);
    }
    detail.push_str(&format!(
        "\n{} accepts connections on:\n{}",
        first.process,
        sockets.join("\n")
    ));
    detail.push_str(&executable(first));
    let mut f = Finding::new(
        finding_key(first).unwrap_or_default(),
        severity,
        CATEGORY,
        title,
    )
    .detail(detail)
    .topic(topic::OPEN_PORTS)
    .remedy(remedy);
    for l in group {
        f = f.at(location(l));
    }
    f
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn report(list: &[Listening], ignore: &Ignore) -> Report {
    let mut findings = Vec::new();
    let mut passing = Vec::new();
    // Programs that aren't known services, grouped by program name.
    let mut programs: BTreeMap<String, (Kind, Vec<&Listening>)> = BTreeMap::new();
    for l in list {
        if ignore.skips(l) {
            passing.push(format!("{}: {} (ignored)", l.process, l.sockets()));
            continue;
        }
        if l.reach() == Reach::Local {
            passing.push(format!(
                "{}: {} (this machine only)",
                l.process,
                l.sockets()
            ));
            continue;
        }
        match classify(l) {
            Kind::Service(s) => findings.push(service_finding(l, s)),
            kind => programs
                .entry(key_part(&l.process))
                .or_insert_with(|| (kind, Vec::new()))
                .1
                .push(l),
        }
    }
    for (kind, group) in programs.values() {
        findings.push(program_finding(kind, group));
    }
    findings.sort_by(super::by_severity);

    let programs_where = |reach: Reach, ignored: bool| -> BTreeSet<&str> {
        list.iter()
            .filter(|l| l.reach() == reach && ignore.skips(l) == ignored)
            .map(|l| l.process.as_str())
            .collect()
    };
    let reachable = programs_where(Reach::Network, false);
    let all: BTreeSet<&str> = list.iter().map(|l| l.process.as_str()).collect();
    let summary = if list.is_empty() {
        "Nothing running as you is listening for connections".to_string()
    } else if reachable.is_empty() {
        let ignored = programs_where(Reach::Network, true).len();
        let except = if ignored > 0 {
            format!(", besides {ignored} you ignored")
        } else {
            String::new()
        };
        format!("No listening program accepts connections from your network{except}")
    } else {
        format!(
            "{} of {} listening programs accept connections from your network",
            reachable.len(),
            all.len()
        )
    };
    Report {
        findings,
        summary,
        passing,
        ..Report::default()
    }
}

impl Lens for ListeningPorts {
    fn id(&self) -> &str {
        ID
    }
    fn title(&self) -> &str {
        "Listening ports"
    }
    fn categories(&self) -> &[Category] {
        &[Category::Network]
    }
    fn description(&self) -> &str {
        "Programs that other devices on your network can connect to: development servers, debuggers, databases and \
         container ports bound to every interface instead of localhost. Only programs running as you are visible."
    }
    fn default_interval(&self) -> Duration {
        Duration::from_secs(5 * 60)
    }
    fn run(&self, cx: &Context) -> Result<Report> {
        Ok(report(
            &network::listening()?,
            &Ignore::from_settings(cx.settings),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(process: &str, port: u16, addrs: &[&str]) -> Listening {
        Listening {
            process: process.to_string(),
            path: format!("/opt/{process}"),
            pids: vec![100],
            port,
            addresses: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    fn run(list: &[Listening], ignore: &[&str]) -> Report {
        report(
            list,
            &Ignore(ignore.iter().map(|s| s.to_string()).collect()),
        )
    }

    #[test]
    fn docker_database_is_high_with_a_docker_remedy() {
        let r = run(&[at("com.docker.backend", 5432, &["::"])], &[]);
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert_eq!(f.key, "listen|com.docker.backend|5432");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.category, Category::Network);
        assert_eq!(f.topic, topic::OPEN_PORTS);
        assert_eq!(
            f.title,
            "PostgreSQL (port 5432) is reachable from your network"
        );
        assert!(
            f.detail
                .starts_with("Docker publishes a container's port 5432")
        );
        assert!(f.remedy.contains("127.0.0.1:5432:"), "{}", f.remedy);
        assert!(f.detail.contains("every network interface"));
        assert!(f.locations[0].path.is_none());
    }

    #[test]
    fn native_database_gets_its_own_remedy() {
        let r = run(&[at("postgres", 5433, &["0.0.0.0"])], &[]);
        assert_eq!(r.findings[0].severity, Severity::High);
        assert!(r.findings[0].remedy.contains("listen_addresses"));
    }

    #[test]
    fn debuggers_are_critical() {
        let r = run(&[at("node", 9229, &["0.0.0.0"])], &[]);
        assert_eq!(r.findings[0].severity, Severity::Critical);
        assert!(r.findings[0].title.starts_with("Node.js inspector"));
        // Port 5005 is only JDWP when Java holds it.
        let r = run(
            &[
                at("java", 5005, &["0.0.0.0"]),
                at("other", 5005, &["0.0.0.0"]),
            ],
            &[],
        );
        assert_eq!(r.findings.len(), 2);
        assert_eq!(r.findings[0].severity, Severity::Critical);
        assert_eq!(r.findings[1].severity, Severity::Info);
    }

    #[test]
    fn container_ports_and_dev_servers_group_by_program() {
        let r = run(
            &[
                at("com.docker.backend", 80, &["0.0.0.0"]),
                at("com.docker.backend", 15432, &["0.0.0.0"]),
                at("node", 3000, &["0.0.0.0"]),
                at("node", 5173, &["192.168.1.4"]),
                at("Python", 8000, &["0.0.0.0"]),
            ],
            &[],
        );
        let keys: Vec<(&str, Severity)> = r
            .findings
            .iter()
            .map(|f| (f.key.as_str(), f.severity))
            .collect();
        assert_eq!(
            keys,
            [
                ("listen|com.docker.backend", Severity::Medium),
                ("listen|Python", Severity::Medium),
                ("listen|node", Severity::Medium),
            ]
        );
        let docker = &r.findings[0];
        assert_eq!(
            docker.title,
            "Docker publishes 2 container ports to your network"
        );
        assert_eq!(docker.locations.len(), 2);
        assert_eq!(
            r.findings[2].title,
            "node accepts connections from your network on ports 3000, 5173"
        );
    }

    #[test]
    fn other_apps_are_informational_and_local_ones_pass() {
        let r = run(
            &[
                at("ControlCenter", 7000, &["0.0.0.0", "::"]),
                at("bridge", 1143, &["127.0.0.1"]),
                at("node", 3000, &["::1"]),
            ],
            &[],
        );
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].severity, Severity::Info);
        assert!(!r.findings[0].severity.is_problem());
        assert_eq!(r.passing.len(), 2);
        assert!(r.passing[0].contains("this machine only"));
        assert_eq!(
            r.summary,
            "1 of 3 listening programs accept connections from your network"
        );
    }

    #[test]
    fn ignore_by_port_program_or_both() {
        let list = [
            at("com.docker.backend", 5432, &["0.0.0.0"]),
            at("com.docker.backend", 6379, &["0.0.0.0"]),
            at("Orca", 6768, &["0.0.0.0"]),
        ];
        assert_eq!(run(&list, &["5432", "orca"]).findings.len(), 1);
        assert_eq!(run(&list, &["com.docker.backend:6379"]).findings.len(), 2);
        let helper = [at("OrbStack Helper", 80, &["0.0.0.0"])];
        assert!(run(&helper, &["orbstack_helper"]).findings.is_empty());
        assert!(run(&helper, &["orbstack helper:80"]).findings.is_empty());
        let r = run(&list, &["com.docker.backend", "orca"]);
        assert!(r.findings.is_empty());
        assert!(r.passing.iter().all(|p| p.ends_with("(ignored)")));
        assert_eq!(
            r.summary,
            "No listening program accepts connections from your network, besides 2 you ignored"
        );
    }

    #[test]
    fn nothing_reachable() {
        assert_eq!(
            run(&[], &[]).summary,
            "Nothing running as you is listening for connections"
        );
        assert_eq!(
            run(&[at("bridge", 1025, &["127.0.0.1"])], &[]).summary,
            "No listening program accepts connections from your network"
        );
    }
}
