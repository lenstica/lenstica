//! Virtual machines: Lima, Colima, Podman machines, Multipass, Tart,
//! VirtualBox and Parallels through their command-line tools, and UTM,
//! VMware Fusion and Vagrant from the files they keep. Only listing commands
//! run; nothing is started.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Asset, Ctx, Found, Status, bytes, field, file_name, json_items, list_with, subdirs};
use crate::paths::home;

/// A tool that lists machines: its binary, its name, the arguments, and how to read what it prints.
type Lister = (
    &'static str,
    &'static str,
    &'static [&'static str],
    fn(&str) -> Vec<Asset>,
);

pub(super) fn discover(ctx: &Ctx, found: &mut Found) {
    let tools: [Lister; 6] = [
        ("limactl", "Lima", &["list", "--format", "json"], lima),
        ("colima", "Colima", &["list", "--json"], colima),
        (
            "podman",
            "Podman",
            &["machine", "list", "--format", "json"],
            podman,
        ),
        (
            "multipass",
            "Multipass",
            &["list", "--format", "json"],
            multipass,
        ),
        ("tart", "Tart", &["list", "--format", "json"], tart),
        (
            "prlctl",
            "Parallels",
            &["list", "--all", "--json"],
            parallels,
        ),
    ];
    for (binary, source, args, parse) in tools {
        let Some(program) = ctx.find(binary) else {
            continue;
        };
        if let Some(out) = list_with(ctx, found, source, &program, args) {
            for a in parse(&out) {
                found.add(a);
            }
        }
    }
    if let Some(vbox) = ctx.find("VBoxManage").or_else(|| ctx.find("vboxmanage")) {
        let running = ctx
            .run(&vbox, &["list", "runningvms"])
            .map(|o| vbox_list(&o.stdout))
            .unwrap_or_default();
        if let Some(out) = list_with(ctx, found, "VirtualBox", &vbox, &["list", "vms"]) {
            for (name, uuid) in vbox_list(&out) {
                let on = running.iter().any(|(_, u)| *u == uuid);
                found.add(
                    Asset::new(format!("vbox:{uuid}"), name, "VirtualBox").status(Some(if on {
                        Status::Running
                    } else {
                        Status::Stopped
                    })),
                );
            }
        }
    }
    utm(found);
    vmware(ctx, found);
    vagrant(found);
}

/// `limactl list --format json`: one object per line.
fn lima(out: &str) -> Vec<Asset> {
    json_items(out)
        .iter()
        .map(|m| {
            let name = field(m, &["name"]).unwrap_or_default();
            let mut a = Asset::new(format!("lima:{name}"), name, "Lima")
                .status(Status::parse(&field(m, &["status"]).unwrap_or_default()))
                .fact_opt("arch", field(m, &["arch"]))
                .fact_opt("type", field(m, &["vmType"]))
                .fact_opt("cpus", field(m, &["cpus"]))
                .fact_opt("memory", m.get("memory").and_then(Value::as_u64).map(bytes))
                .fact_opt("disk", m.get("disk").and_then(Value::as_u64).map(bytes));
            if let Some(dir) = field(m, &["dir"]) {
                a = a.path(dir);
            }
            a
        })
        .collect()
}

/// `colima list --json`: one object per line.
fn colima(out: &str) -> Vec<Asset> {
    json_items(out)
        .iter()
        .map(|m| {
            let name = field(m, &["name"]).unwrap_or_default();
            Asset::new(format!("colima:{name}"), name.clone(), "Colima")
                .path(home().join(".colima").join(&name))
                .status(Status::parse(&field(m, &["status"]).unwrap_or_default()))
                .fact_opt("arch", field(m, &["arch"]))
                .fact_opt("type", field(m, &["runtime"]))
                .fact_opt("cpus", field(m, &["cpus"]))
                .fact_opt("memory", m.get("memory").and_then(Value::as_u64).map(bytes))
                .fact_opt("disk", m.get("disk").and_then(Value::as_u64).map(bytes))
                .fact_opt("address", field(m, &["address"]))
        })
        .collect()
}

/// `podman machine list --format json`: an array.
fn podman(out: &str) -> Vec<Asset> {
    json_items(out)
        .iter()
        .map(|m| {
            let name = field(m, &["Name"]).unwrap_or_default();
            let running = m.get("Running").and_then(Value::as_bool).unwrap_or(false);
            let size = |k: &str| {
                m.get(k).and_then(|v| {
                    v.as_u64()
                        .map(bytes)
                        .or_else(|| v.as_str().map(str::to_string))
                })
            };
            Asset::new(
                format!("podman:{name}"),
                name.trim_end_matches('*'),
                "Podman",
            )
            .status(Some(if running {
                Status::Running
            } else {
                Status::Stopped
            }))
            .fact_opt("type", field(m, &["VMType"]))
            .fact_opt("cpus", field(m, &["CPUs"]))
            .fact_opt("memory", size("Memory"))
            .fact_opt("disk", size("DiskSize"))
            .tag_if(
                m.get("Default").and_then(Value::as_bool) == Some(true),
                "current",
            )
        })
        .collect()
}

/// `multipass list --format json`: `{"list": […]}`.
fn multipass(out: &str) -> Vec<Asset> {
    let doc: Value = serde_json::from_str(out.trim()).unwrap_or_default();
    doc.get("list")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|m| {
            let name = field(m, &["name"]).unwrap_or_default();
            let ip = m
                .get("ipv4")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .map(str::to_string);
            Asset::new(format!("multipass:{name}"), name, "Multipass")
                .status(Status::parse(&field(m, &["state"]).unwrap_or_default()))
                .fact_opt("system", field(m, &["release"]))
                .fact_opt("address", ip)
        })
        .collect()
}

/// `tart list --format json`: an array of local and pulled images; only
/// local machines are VMs.
fn tart(out: &str) -> Vec<Asset> {
    json_items(out)
        .iter()
        .filter(|m| field(m, &["Source"]).is_none_or(|s| s.eq_ignore_ascii_case("local")))
        .map(|m| {
            let name = field(m, &["Name"]).unwrap_or_default();
            let running = m.get("Running").and_then(Value::as_bool);
            let status = match running {
                Some(true) => Some(Status::Running),
                Some(false) => Some(Status::Stopped),
                None => Status::parse(&field(m, &["State"]).unwrap_or_default()),
            };
            Asset::new(format!("tart:{name}"), name.clone(), "Tart")
                .path(home().join(".tart/vms").join(&name))
                .status(status)
                .fact_opt("disk", field(m, &["Disk"]).map(|d| format!("{d} GB")))
        })
        .collect()
}

/// `prlctl list --all --json`: an array.
fn parallels(out: &str) -> Vec<Asset> {
    json_items(out)
        .iter()
        .map(|m| {
            let uuid = field(m, &["uuid"]).unwrap_or_default();
            Asset::new(
                format!("parallels:{uuid}"),
                field(m, &["name"]).unwrap_or_default(),
                "Parallels",
            )
            .status(Status::parse(&field(m, &["status"]).unwrap_or_default()))
            .fact_opt(
                "address",
                field(m, &["ip_configured"]).filter(|ip| ip != "-"),
            )
        })
        .collect()
}

/// `"Ubuntu" {0e3c…}` lines.
fn vbox_list(out: &str) -> Vec<(String, String)> {
    out.lines()
        .filter_map(|l| {
            let (name, rest) = l.trim().strip_prefix('"')?.rsplit_once("\" {")?;
            Some((name.to_string(), rest.trim_end_matches('}').to_string()))
        })
        .collect()
}

/// UTM keeps each machine as a `.utm` bundle in its sandbox, which macOS
/// only lets other apps read with Full Disk Access (and otherwise asks the
/// user), so without it UTM is noted as blocked rather than read.
fn utm(found: &mut Found) {
    let container = home().join("Library/Containers/com.utmapp.UTM");
    if !container.exists() {
        return;
    }
    if !super::full_disk_access() {
        found.blocked.push("UTM".to_string());
        return;
    }
    let docs = container.join("Data/Documents");
    for vm in subdirs(&docs)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "utm"))
    {
        let name = file_name(&vm).trim_end_matches(".utm").to_string();
        found.add(Asset::new(format!("utm:{name}"), name, "UTM").path(vm));
    }
}

/// VMware Fusion's `.vmwarevm` bundles, running when `vmrun list` names their `.vmx`.
fn vmware(ctx: &Ctx, found: &mut Found) {
    let h = home();
    let bundles: Vec<PathBuf> = [
        h.join("Virtual Machines.localized"),
        h.join("Virtual Machines"),
    ]
    .iter()
    .flat_map(|d| subdirs(d))
    .filter(|p| p.extension().is_some_and(|e| e == "vmwarevm"))
    .collect();
    if bundles.is_empty() {
        return;
    }
    let running: Vec<String> = ctx
        .find("vmrun")
        .and_then(|vmrun| ctx.run(&vmrun, &["list"]).ok())
        .map(|o| o.stdout.lines().skip(1).map(str::to_string).collect())
        .unwrap_or_default();
    for vm in bundles {
        let on = running.iter().any(|r| Path::new(r).starts_with(&vm));
        let name = file_name(&vm).trim_end_matches(".vmwarevm").to_string();
        found.add(
            Asset::new(format!("vmware:{}", vm.display()), name, "VMware Fusion")
                .path(vm)
                .status(Some(if on { Status::Running } else { Status::Stopped })),
        );
    }
}

/// Vagrant's machine index: every machine any Vagrantfile brought up.
fn vagrant(found: &mut Found) {
    let index = home().join(".vagrant.d/data/machine-index/index");
    let Some(doc) = crate::files::read_json::<Value>(&index) else {
        return;
    };
    for a in vagrant_machines(&doc) {
        found.add(a);
    }
}

fn vagrant_machines(doc: &Value) -> Vec<Asset> {
    doc.get("machines")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(id, m)| {
            let name = field(m, &["name"]).unwrap_or_else(|| "default".to_string());
            let folder = field(m, &["vagrantfile_path"]);
            // Most Vagrantfiles name their one machine `default`: the folder says which.
            let shown = match (&folder, name.as_str()) {
                (Some(f), "default") => file_name(Path::new(f)),
                _ => name,
            };
            let mut a = Asset::new(format!("vagrant:{id}"), shown, "Vagrant")
                .status(Status::parse(&field(m, &["state"]).unwrap_or_default()))
                .fact_opt("type", field(m, &["provider"]))
                .fact_opt(
                    "folder",
                    folder.as_deref().map(|f| crate::paths::tilde(Path::new(f))),
                );
            if let Some(f) = folder {
                a = a.path(f);
            }
            a
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lima_instances() {
        let out = r#"{"name":"default","status":"Stopped","dir":"/Users/a/.lima/default","vmType":"vz","arch":"aarch64","cpus":4,"memory":4294967296,"disk":107374182400}"#;
        let list = lima(out);
        assert_eq!(list[0].name, "default");
        assert_eq!(list[0].status, Some(Status::Stopped));
        assert_eq!(list[0].get("memory"), Some("4 GB"));
        assert_eq!(list[0].get("disk"), Some("100 GB"));
        assert_eq!(list[0].get("cpus"), Some("4"));
    }

    #[test]
    fn other_tools() {
        let list = multipass(
            r#"{"list":[{"ipv4":["192.168.64.2"],"name":"primary","release":"Ubuntu 24.04 LTS","state":"Running"}]}"#,
        );
        assert_eq!(list[0].status, Some(Status::Running));
        assert_eq!(list[0].get("address"), Some("192.168.64.2"));

        let list = podman(
            r#"[{"Name":"podman-machine-default*","Default":true,"Running":false,"VMType":"applehv","CPUs":5,"Memory":"2147483648","DiskSize":"100"}]"#,
        );
        assert_eq!(list[0].name, "podman-machine-default");
        assert_eq!(list[0].status, Some(Status::Stopped));

        let list = parallels(
            r#"[{"uuid":"{1}","status":"stopped","ip_configured":"-","name":"Windows 11"}]"#,
        );
        assert_eq!(list[0].name, "Windows 11");
        assert!(list[0].get("address").is_none());

        let list = tart(
            r#"[{"Name":"sonoma","Source":"local","Running":true,"Disk":50},{"Name":"ghcr.io/x:latest","Source":"OCI"}]"#,
        );
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].status, Some(Status::Running));

        assert_eq!(
            vbox_list("\"Ubuntu 24\" {0e3c-11}\n"),
            [("Ubuntu 24".to_string(), "0e3c-11".to_string())]
        );
    }

    #[test]
    fn vagrant_names_default_machines_by_folder() {
        let doc: Value = serde_json::from_str(r#"{"version":1,"machines":{"abc":{"name":"default","provider":"virtualbox","state":"poweroff","vagrantfile_path":"/Users/a/dev/box"}}}"#).unwrap();
        let list = vagrant_machines(&doc);
        assert_eq!(list[0].name, "box");
        assert_eq!(list[0].status, Some(Status::Stopped));
        assert_eq!(list[0].get("type"), Some("virtualbox"));
    }
}
