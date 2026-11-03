//! Containers, running and stopped, from the Docker and Podman command-line
//! tools. Docker's tool answers for whichever engine its current context
//! points at (Docker Desktop, OrbStack, Colima, Rancher Desktop), so that is
//! the source shown. Nothing is started: an engine that is not running is
//! noted, and its containers are left out.

use serde_json::Value;

use super::{Asset, Ctx, Found, Status, day_from_epoch, field, json_items, list_with};

pub(super) fn discover(ctx: &Ctx, found: &mut Found) {
    if let Some(docker) = ctx.find("docker") {
        let engine = ctx
            .run(&docker, &["context", "ls", "--format", "{{json .}}"])
            .ok()
            .map(|o| engine_name(&o.stdout))
            .unwrap_or_else(|| "Docker".to_string());
        if let Some(out) = list_with(
            ctx,
            found,
            &engine,
            &docker,
            &["ps", "--all", "--no-trunc", "--format", "{{json .}}"],
        ) {
            for c in json_items(&out) {
                found.add(docker_container(&c, &engine));
            }
        }
    }
    if let Some(podman) = ctx.find("podman")
        && let Some(out) = list_with(
            ctx,
            found,
            "Podman",
            &podman,
            &["ps", "--all", "--format", "json"],
        )
    {
        for c in json_items(&out) {
            found.add(podman_container(&c));
        }
    }
}

/// The current Docker context, named for the app behind it.
fn engine_name(contexts: &str) -> String {
    let current = json_items(contexts)
        .into_iter()
        .find(|c| c.get("Current").and_then(Value::as_bool) == Some(true));
    let Some(c) = current else {
        return "Docker".to_string();
    };
    let name = field(&c, &["Name"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let endpoint = field(&c, &["DockerEndpoint"]).unwrap_or_default();
    if name == "desktop-linux" || name.starts_with("desktop") {
        "Docker Desktop"
    } else if name.contains("orbstack") || endpoint.contains(".orbstack") {
        "OrbStack"
    } else if name.starts_with("colima") || endpoint.contains(".colima") {
        "Colima"
    } else if name.contains("rancher") || endpoint.contains(".rd/") {
        "Rancher Desktop"
    } else {
        "Docker"
    }
    .to_string()
}

/// `kindest/node:v1.37.0@sha256:…` -> `kindest/node:v1.37.0`.
fn image_name(image: &str) -> String {
    image.split('@').next().unwrap_or(image).to_string()
}

/// One line of `docker ps --format '{{json .}}'`.
fn docker_container(c: &Value, engine: &str) -> Asset {
    let id = field(c, &["ID"]).unwrap_or_default();
    let name = field(c, &["Names"]).unwrap_or_else(|| id.chars().take(12).collect());
    let labels = field(c, &["Labels"]).unwrap_or_default();
    let project = labels
        .split(',')
        .find_map(|l| l.strip_prefix("com.docker.compose.project="))
        .map(str::to_string);
    let created = field(c, &["CreatedAt"]).map(|s| s.chars().take(10).collect::<String>());
    Asset::new(format!("docker:{id}"), name, engine)
        .status(Status::parse(
            &field(c, &["State"])
                .or_else(|| field(c, &["Status"]))
                .unwrap_or_default(),
        ))
        .fact_opt("image", field(c, &["Image"]).map(|i| image_name(&i)))
        .fact_opt("state", field(c, &["Status"]))
        .fact_opt("ports", field(c, &["Ports"]))
        .fact_opt("project", project)
        .fact_opt("created", created)
        .fact("id", id.chars().take(12).collect::<String>())
}

/// One item of `podman ps --format json`.
fn podman_container(c: &Value) -> Asset {
    let id = field(c, &["Id", "ID"]).unwrap_or_default();
    let name = c
        .get("Names")
        .and_then(Value::as_array)
        .and_then(|n| n.first())
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| id.chars().take(12).collect());
    let ports: Vec<String> = c
        .get("Ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|p| {
            let host = p.get("host_port").and_then(Value::as_u64)?;
            let inside = p.get("container_port").and_then(Value::as_u64)?;
            let ip = p
                .get("host_ip")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("0.0.0.0");
            let proto = p.get("protocol").and_then(Value::as_str).unwrap_or("tcp");
            Some(format!("{ip}:{host}->{inside}/{proto}"))
        })
        .collect();
    let project = c
        .pointer("/Labels/com.docker.compose.project")
        .and_then(Value::as_str)
        .map(str::to_string);
    Asset::new(format!("podman:{id}"), name, "Podman")
        .status(Status::parse(&field(c, &["State"]).unwrap_or_default()))
        .fact_opt("image", field(c, &["Image"]).map(|i| image_name(&i)))
        .fact_opt("state", field(c, &["Status"]))
        .fact("ports", ports.join(", "))
        .fact_opt("project", project)
        .fact_opt(
            "created",
            c.get("Created")
                .and_then(Value::as_i64)
                .and_then(day_from_epoch),
        )
        .fact("id", id.chars().take(12).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_lines() {
        let line = r#"{"CreatedAt":"2026-09-25 21:41:56 -0400 EDT","ID":"0c6d7ec1b52aa6e0198d054991a753640f7d03fb0dcf94e20351eeb254701029","Image":"registry:2@sha256:abc","Labels":"com.docker.compose.project=web,x=y","Names":"kind-registry","Ports":"127.0.0.1:5001->5000/tcp","State":"running","Status":"Up 5 weeks"}"#;
        let a = docker_container(&serde_json::from_str(line).unwrap(), "Docker Desktop");
        assert_eq!(a.name, "kind-registry");
        assert_eq!(a.source, "Docker Desktop");
        assert_eq!(a.status, Some(Status::Running));
        assert_eq!(a.get("image"), Some("registry:2"));
        assert_eq!(a.get("project"), Some("web"));
        assert_eq!(a.get("created"), Some("2026-09-25"));
        assert_eq!(a.get("id"), Some("0c6d7ec1b52a"));
    }

    #[test]
    fn podman_items() {
        let item = r#"{"Id":"abcdef0123456789","Names":["db"],"Image":"docker.io/library/postgres:17","State":"exited","Status":"Exited (0) 2 days ago","Created":1792610529,"Ports":[{"host_ip":"","container_port":5432,"host_port":5432,"range":1,"protocol":"tcp"}]}"#;
        let a = podman_container(&serde_json::from_str(item).unwrap());
        assert_eq!(a.name, "db");
        assert_eq!(a.status, Some(Status::Stopped));
        assert_eq!(a.get("ports"), Some("0.0.0.0:5432->5432/tcp"));
        assert_eq!(a.get("created"), Some("2026-10-21"));
    }

    #[test]
    fn engines_by_context() {
        let ls = "{\"Current\":false,\"Name\":\"default\",\"DockerEndpoint\":\"unix:///var/run/docker.sock\"}\n{\"Current\":true,\"Name\":\"desktop-linux\",\"DockerEndpoint\":\"unix:///Users/a/.docker/run/docker.sock\"}\n";
        assert_eq!(engine_name(ls), "Docker Desktop");
        assert_eq!(
            engine_name("{\"Current\":true,\"Name\":\"orbstack\"}"),
            "OrbStack"
        );
        assert_eq!(
            engine_name(
                "{\"Current\":true,\"Name\":\"default\",\"DockerEndpoint\":\"unix:///Users/a/.colima/default/docker.sock\"}"
            ),
            "Colima"
        );
        assert_eq!(engine_name(""), "Docker");
    }
}
