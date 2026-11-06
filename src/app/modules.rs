//! What each key needs. A page belongs to a module, but keys reach across
//! pages: `m` records a finding from anywhere, `D` traces from four pages.
//! This table is the one place that says so: hints, key handling, menus and
//! the command palette all read it, so none can offer what isn't loaded.

use super::*;

/// The module a key needs on this page, beyond the page's own.
pub fn key_needs(tab: Tab, key: &str) -> Option<&'static str> {
    Some(match (key, tab) {
        ("f" | "W", _) => "process",
        ("D", Tab::Processes | Tab::Network | Tab::Timeline | Tab::Alerts) => "trace",
        ("T", Tab::Processes) => "trace",
        ("l", Tab::Performance | Tab::Case | Tab::Trace) => return None,
        ("l", _) => "timeline",
        ("m", Tab::Performance) => return None,
        ("m", _) => "case",
        ("Q", Tab::Files | Tab::Persistence) => "case",
        ("b" | "B", Tab::Timeline) => "case",
        ("e", Tab::Activity) => "case",
        ("P", Tab::Defense) => "process",
        ("I" | "Y", Tab::Case) => "detection",
        ("1", Tab::Trace) => "process",
        ("enter", Tab::Network | Tab::Timeline | Tab::Logs | Tab::Trace) => "process",
        _ => return None,
    })
}

impl App {
    /// True if the module is loaded; otherwise says so.
    pub fn require(&mut self, module: &str) -> bool {
        let on = self.module_on(module);
        if !on {
            self.set_status(StatusLevel::Info, format!("The {module} module isn't loaded. Press M to load it."));
        }
        on
    }

    /// What a key needs where it would be pressed now, overlays included.
    fn needs_now(&self, key: &str) -> Option<&'static str> {
        match (&self.mode, key) {
            (Mode::Normal, _) => match (self.tab, key) {
                (Tab::Files, "enter") if !self.ir.files_changes_view => Some("process"),
                (tab, _) => key_needs(tab, key),
            },
            (Mode::FileReport, "m" | "Q") | (Mode::Sweep, "m") => Some("case"),
            (Mode::Workspace, "D") => Some("trace"),
            (Mode::Graph, "t") => Some("timeline"),
            _ => None,
        }
    }

    /// Whether a key does anything here. Hints show only those that do.
    pub fn key_on(&self, key: &str) -> bool {
        self.needs_now(key).is_none_or(|m| self.module_on(m))
    }

    /// Commands that can run now.
    pub fn palette_entries(&self, query: &str) -> Vec<&'static palette::Entry> {
        let usable = |e: &&palette::Entry| {
            let page = e.tab.or_else(|| Tab::ALL.into_iter().find(|t| t.key() == e.key));
            page.is_none_or(|t| self.tab_on(t)) && key_needs(e.tab.unwrap_or(self.tab), e.key.encode_utf8(&mut [0; 4])).is_none_or(|m| self.module_on(m))
        };
        palette::matches(query).into_iter().filter(usable).collect()
    }
}
