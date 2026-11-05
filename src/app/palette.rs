//! Command palette: every action by name, so nobody has to remember keys.
//! Each entry names the page it acts on and the key it stands for; running
//! it switches page and replays that key.

use crate::app::Tab;

pub struct Entry {
    pub label: &'static str,
    pub tab: Option<Tab>,
    pub key: char,
    pub hint: &'static str,
}

const fn e(label: &'static str, tab: Option<Tab>, key: char, hint: &'static str) -> Entry {
    Entry { label, tab, key, hint }
}

pub static ENTRIES: &[Entry] = &[
    e("Go to Processes", None, '1', "1"),
    e("Go to Performance", None, '2', "2"),
    e("Go to Network", None, '3', "3"),
    e("Go to Files", None, '4', "4"),
    e("Go to Persistence", None, '5', "5"),
    e("Go to Timeline", None, '6', "6"),
    e("Go to Logs", None, '7', "7"),
    e("Go to Trace", None, '8', "8"),
    e("Go to Detect (detections, alerts, rules)", None, '9', "9"),
    e("Go to Case", None, '0', "0"),
    e("Go to Activity (file, registry and network operations)", None, '`', "`"),
    e("Start or stop activity capture", Some(Tab::Activity), 'c', "Act c"),
    e("Clear captured activity", Some(Tab::Activity), 'x', "Act x"),
    e("Activity summary: busiest processes and targets", Some(Tab::Activity), 's', "Act s"),
    e("Save captured activity to the case", Some(Tab::Activity), 'e', "Act e"),
    e("Investigation workspace for the selected process", None, 'W', "W"),
    e("Deep trace the selected process (event-driven)", None, 'D', "D"),
    e("Investigation graph of the selected item", None, 'l', "l"),
    e("Collection health — what can and can't be seen", None, 'H', "H"),
    e("Trace behavior of the selected process (sampled)", Some(Tab::Processes), 'T', "T"),
    e("Search / filter", None, '/', "/"),
    e("Find who has a file or port open", None, 'f', "f"),
    e("Pause / resume updates", None, 'p', "p"),
    e("Options", None, 'o', "o"),
    e("Help: keys and mouse", None, '?', "?"),
    e("Remote hosts and beaconing", Some(Tab::Network), 'h', "Net h"),
    e("DNS view", Some(Tab::Network), 'd', "Net d"),
    e("Analyze a file by path…", Some(Tab::Files), 'A', "Files A"),
    e("Open files / file changes", Some(Tab::Files), 'w', "Files w"),
    e("Rescan autostart entries", Some(Tab::Persistence), 'r', "Persist r"),
    e("Changes since baseline", Some(Tab::Persistence), 'c', "Persist c"),
    e("Activity clusters (correlated behaviour)", Some(Tab::Timeline), 'c', "Time c"),
    e("System state at the selected event", Some(Tab::Timeline), 's', "Time s"),
    e("Bookmark the selected event…", Some(Tab::Timeline), 'b', "Time b"),
    e("Export timeline CSV", Some(Tab::Timeline), 'e', "Time e"),
    e("Event log: time window", Some(Tab::Logs), 'w', "Logs w"),
    e("Execution artifacts (Prefetch, Amcache, history…)", Some(Tab::Logs), 'x', "Logs x"),
    e("Suppress the selected detection…", Some(Tab::Alerts), 'S', "Detect S"),
    e("Trust the selected program's publisher…", Some(Tab::Alerts), 'T', "Detect T"),
    e("Show / hide suppressed detections", Some(Tab::Alerts), 'u', "Detect u"),
    e("Reload Sigma rules and suppressions", Some(Tab::Alerts), 'R', "Detect R"),
    e("New case", Some(Tab::Case), 'n', "Case n"),
    e("Collect system evidence", Some(Tab::Case), 'c', "Case c"),
    e("Seal evidence (SHA-256 manifest)", Some(Tab::Case), 's', "Case s"),
    e("Verify evidence and custody chain", Some(Tab::Case), 'v', "Case v"),
    e("IOC sweep against an indicator file…", Some(Tab::Case), 'I', "Case I"),
    e("Content scan (YARA) of running executables", Some(Tab::Case), 'Y', "Case Y"),
    e("Export report (Markdown, JSON, HTML)", Some(Tab::Case), 'e', "Case e"),
    e("Export STIX 2.1, MISP event and ECS timeline", Some(Tab::Case), 'X', "Case X"),
    e("Network isolation scripts (written, not run)…", Some(Tab::Case), 'i', "Case i"),
    e("Add analyst note…", Some(Tab::Case), 'a', "Case a"),
    e("Set investigation conclusion…", Some(Tab::Case), 'C', "Case C"),
    e("Quit", None, 'q', "q"),
];

/// Subsequence match score (higher is better), None if no match.
pub fn score(query: &str, label: &str) -> Option<i32> {
    let q: Vec<char> = query.to_lowercase().chars().filter(|c| !c.is_whitespace()).collect();
    if q.is_empty() {
        return Some(0);
    }
    let l: Vec<char> = label.to_lowercase().chars().collect();
    let (mut i, mut score, mut last) = (0, 0i32, None::<usize>);
    for (j, c) in l.iter().enumerate() {
        if i < q.len() && *c == q[i] {
            score += if last == Some(j.wrapping_sub(1)) { 5 } else { 1 };
            if j == 0 || l[j - 1] == ' ' {
                score += 3;
            }
            last = Some(j);
            i += 1;
        }
    }
    (i == q.len()).then_some(score - l.len() as i32 / 20)
}

pub fn matches(query: &str) -> Vec<&'static Entry> {
    let mut v: Vec<(i32, &Entry)> = ENTRIES.iter().filter_map(|e| score(query, e.label).map(|s| (s, e))).collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.0));
    v.into_iter().map(|(_, e)| e).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_finds_actions() {
        assert_eq!(matches("stix")[0].key, 'X');
        assert_eq!(matches("deep tr")[0].key, 'D');
        assert_eq!(matches("wkspc")[0].key, 'W');
        assert!(matches("zzzz").is_empty());
        assert_eq!(matches("").len(), ENTRIES.len());
    }
}
