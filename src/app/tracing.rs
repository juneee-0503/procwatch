//! Behaviour trace control.

use super::*;

impl App {
    // ── behavior trace ─────────────────────────────────────────────────

    pub fn start_trace(&mut self, pid: u32) {
        if !self.tab_on(Tab::Trace) {
            self.set_status(StatusLevel::Info, "The trace module isn't loaded. Press M to load it.".into());
            return;
        }
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        if pid == std::process::id() {
            self.set_status(StatusLevel::Error, "procwatch can't trace itself".into());
            return;
        }
        self.stop_trace();
        let Some(t) = Trace::new(pid, &self.tree, &self.connections) else {
            self.set_status(StatusLevel::Error, format!("Process {pid} is no longer running"));
            return;
        };
        if let Ok(mut targets) = self.trace_targets.lock() {
            *targets = t.live_pids();
        }
        let stop = Arc::new(AtomicBool::new(false));
        self.trace_stop = stop.clone();
        crate::engine::jobs::spawn_trace_poller(self.tx.clone(), self.trace_targets.clone(), stop);
        self.set_status(StatusLevel::Success, format!("Tracing {} ({pid}) and its child processes", t.root_name));
        self.trace = Some(t);
        // A leftover search from the Processes page would hide events.
        self.query.clear();
        self.rebuild();
        self.trace_selected = 0;
        self.trace_offset = 0;
        self.trace_follow = true;
        self.tab = Tab::Trace;
        self.detail_full = false;
    }

    pub fn stop_trace(&mut self) {
        self.trace_stop.store(true, Ordering::Relaxed);
        let mut stopped = None;
        if let Some(t) = self.trace.as_mut() {
            if t.is_running() {
                t.stop();
                stopped = Some(t.elapsed().as_secs_f64());
            }
        }
        if let Some(secs) = stopped {
            self.set_status(StatusLevel::Info, format!("Trace stopped after {secs:.0}s — press e to export a report"));
        }
    }

    pub fn export_trace(&mut self) {
        let Some(t) = self.trace.as_ref() else { return };
        match t.export() {
            Ok(base) => self.set_status(StatusLevel::Success, format!("Report saved: {base}.md and {base}.json")),
            Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't save report: {e}")),
        }
    }

    /// Indices of trace events passing the category filter and search.
    pub fn visible_trace(&self) -> Vec<usize> {
        let Some(t) = self.trace.as_ref() else { return Vec::new() };
        let f = Filter::parse(&self.query);
        t.events
            .iter()
            .enumerate()
            .filter(|(_, e)| self.trace_filter.matches(e.kind))
            .filter(|(_, e)| f.matches(*e))
            .map(|(i, _)| i)
            .collect()
    }

    pub(crate) fn follow_trace(&mut self) {
        if self.trace_follow {
            self.trace_selected = self.visible_trace().len().saturating_sub(1);
        }
    }

    pub fn is_new(&self, pid: u32) -> bool {
        self.highlight_new
            && self.first_seen.get(&pid).is_some_and(|s| *s > 0 && self.seq.saturating_sub(*s) < NEW_HIGHLIGHT_SAMPLES)
    }

    /// Periodic housekeeping between frames. Returns true if anything
    /// visible changed and a redraw is needed.
    pub fn on_tick(&mut self) -> bool {
        self.tick = self.tick.wrapping_add(1);
        let mut dirty = self.is_busy() | self.boot_tick() | self.board_tick();
        if self.status.as_ref().is_some_and(|s| s.at.elapsed() > STATUS_TTL) {
            self.status = None;
            dirty = true;
        }
        if self.details_visible() && self.pane_tab.needs_inspection() && self.selection_changed.elapsed() >= INSPECT_DEBOUNCE
        {
            dirty |= self.request_deep_info(false);
        }
        if self.details_visible() && self.pane_tab == PaneTab::Stack && self.selection_changed.elapsed() >= INSPECT_DEBOUNCE {
            dirty |= self.request_stack(false);
        }
        if self.tab == Tab::Files && self.files.is_none() {
            self.refresh_files();
            dirty = true;
        }
        dirty |= self.ir_on_tick();
        if self.hold_until.is_some_and(|t| Instant::now() >= t) {
            // Hold expired: catch up with the real sort order.
            self.hold_until = None;
            self.rebuild();
            dirty = true;
        }
        dirty
    }

    /// Whether rows currently keep their previous order.
    pub fn order_held(&self) -> bool {
        self.order_frozen || self.hold_until.is_some_and(|t| Instant::now() < t)
    }

    pub fn hold_order_now(&mut self) {
        self.hold_order();
    }

    pub(crate) fn hold_order(&mut self) {
        if self.tab == Tab::Processes {
            self.hold_until = Some(Instant::now() + ORDER_HOLD);
        }
    }

    pub fn toggle_freeze(&mut self) {
        self.order_frozen = !self.order_frozen;
        self.hold_until = None;
        if !self.order_frozen {
            self.rebuild();
        }
        self.set_status(
            StatusLevel::Info,
            if self.order_frozen {
                "List order frozen — values still update; press z to unfreeze"
            } else {
                "List order follows the sort again"
            }
            .into(),
        );
    }

    pub fn is_busy(&self) -> bool {
        !self.loaded
            || self.actions_pending > 0
            || self.find.as_ref().is_some_and(|f| f.pending)
            || self.detail_pid().is_some_and(|p| self.deep_pending.contains(&p))
            || self.ir_busy()
            || self.board.worst().is_some()
            || !matches!(self.boot.phase, crate::app::boot::BootPhase::Monitoring | crate::app::boot::BootPhase::Standby)
    }

    pub fn is_stale(&self) -> bool {
        self.loaded
            && !self.ctl.paused.load(Ordering::Relaxed)
            && self.last_snapshot.elapsed() > self.ctl.interval() * 3 + Duration::from_secs(2)
    }
}
