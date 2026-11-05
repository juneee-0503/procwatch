//! How investigation items answer filter queries.

use super::*;

impl Filterable for TimelineItem {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "pid" => Some(vec![self.pid.map(|p| p.to_string()).unwrap_or_default()]),
            "tree" => Some(self.lineage.iter().map(|p| p.to_string()).collect()),
            "name" => Some(vec![self.name.clone()]),
            "kind" => Some(vec![self.kind.clone()]),
            "source" => Some(vec![self.source.to_string()]),
            "id" => Some(vec![short_id(self.id).to_lowercase()]),
            "basis" => Some(vec![self.basis.label().into()]),
            "cluster" => Some(vec![self.cluster.map(|c| c.to_string()).unwrap_or_default()]),
            "tag" => Some(vec![self.tag.clone().unwrap_or_default()]),
            "entity" => Some(self.entities().map(|e| e.key()).collect()),
            "path" => Some(self.entities().filter_map(|e| if let Entity::File(p) = e { Some(p.clone()) } else { None }).collect()),
            "port" | "ip" => {
                let eps: Vec<String> = self.detail.split_whitespace().filter(|w| w.contains(':')).map(|w| w.to_string()).collect();
                let mut v: Vec<String> = eps.iter().map(|e| if name == "port" { split_endpoint(e).1 } else { split_endpoint(e).0 }).collect();
                if name == "ip" {
                    v.extend(self.entities().filter_map(|e| if let Entity::Endpoint(ip) = e { Some(ip.clone()) } else { None }));
                }
                Some(v)
            }
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {} {}", self.source, self.kind, self.name, self.pid.map(|p| p.to_string()).unwrap_or_default(), self.detail)
    }
}

impl Filterable for RemoteSummary {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "ip" => Some(vec![self.ip.clone()]),
            "name" => Some(self.processes.iter().cloned().chain(self.host.clone()).collect()),
            "port" => Some(self.ports.clone()),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {}", self.ip, self.host.clone().unwrap_or_default(), self.processes.join(" "), self.ports.join(" "))
    }
}

impl Filterable for PersistItem {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "name" => Some(vec![self.name.clone()]),
            "kind" => Some(vec![self.category.clone()]),
            "path" => Some(vec![self.target.clone().unwrap_or_default(), self.location.clone()]),
            "cmd" => Some(vec![self.command.clone()]),
            "user" => Some(vec![self.scope.clone()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {} {} {}", self.category, self.name, self.command, self.location, self.detail, self.flags.join(" "))
    }
}

impl Filterable for logs::Entry {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "pid" => Some(vec![self.pid.map(|p| p.to_string()).unwrap_or_default()]),
            "name" => Some(vec![self.process.clone()]),
            "kind" => Some(vec![self.level.clone()]),
            "source" => Some(vec![self.source.clone()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {}", self.level, self.process, self.source, self.message)
    }
}

impl Filterable for crate::host::artifacts::Artifact {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "kind" | "source" => Some(vec![self.kind.into()]),
            "path" | "cmd" => Some(vec![self.subject.clone()]),
            "user" => Some(vec![self.user.clone().unwrap_or_default()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {}", self.kind, self.subject, self.detail, self.user.as_deref().unwrap_or(""))
    }
}

impl Ir {
    pub fn traffic_method(&self) -> Option<&'static str> {
        self.traffic.as_ref().map(|t| t.method)
    }
}

impl Filterable for crate::activity::Activity {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "pid" => Some(vec![self.pid.to_string()]),
            "name" => Some(vec![self.name.to_string()]),
            "path" => Some(vec![self.path.clone()]),
            "kind" | "type" => Some(vec![self.op.to_string()]),
            "source" => Some(vec![self.class.label().to_string()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {} {} {}", self.pid, self.name, self.class.label(), self.op, self.path, self.detail)
    }
}

impl Filterable for crate::performance::services::Service {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "name" => Some(vec![self.name.clone()]),
            "state" => Some(vec![self.state.label().to_string()]),
            "pid" => self.pid.map(|p| vec![p.to_string()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {}", self.name, self.state.label(), self.detail)
    }
}

impl Filterable for FsEvent {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "kind" => Some(vec![self.kind.to_string()]),
            "path" => Some(vec![self.path.clone()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {}", self.kind, self.path)
    }
}

