//! Decide what is due every few seconds and run each due lens on its own
//! thread, so a slow one never holds up the others: interval elapsed, a file
//! it watches changed, the settings changed, or someone asked. Results
//! recorded by other processes (`lenstica check`) are picked up too.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use chrono::{DateTime, Utc};
use tauri::{AppHandle, Manager};

use super::{AppState, Request};
use crate::config::{self, Config};
use crate::lenses::{self, store::RunResult};
use crate::managers::{self, Action, Ctx, Mode};
use crate::paths;

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn log(lines: &[String]) {
    let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    for line in lines {
        eprintln!("[{stamp}] {line}");
    }
}

fn with_shared(app: &AppHandle, f: impl FnOnce(&mut super::Shared)) {
    let state = app.state::<AppState>();
    let mut shared = state.lock();
    f(&mut shared);
}

struct Scheduler {
    app: AppHandle,
    done_tx: Sender<RunResult>,
    watched: HashMap<String, Vec<(PathBuf, Option<SystemTime>)>>,
    /// When each lens last ran, by the wall clock (time asleep counts).
    known: HashMap<String, DateTime<Utc>>,
    /// Lenses asked for explicitly, with whether to stay offline.
    forced: BTreeMap<String, bool>,
    force_all: bool,
    /// The last settings that loaded, used while the file is broken.
    last_good: Option<Config>,
    /// The settings error last reported, so it is reported once.
    config_error: Option<String>,
}

pub fn start(app: AppHandle, inbox: Receiver<Request>) {
    thread::spawn(move || {
        let (done_tx, done_rx) = mpsc::channel();
        let mut s = Scheduler {
            app,
            done_tx,
            watched: HashMap::new(),
            known: HashMap::new(),
            forced: BTreeMap::new(),
            force_all: false,
            last_good: None,
            config_error: None,
        };
        // Results already on disk count as runs, so a restart does not redo
        // everything at once; those saved by an older version run again now.
        for r in lenses::store::load().values() {
            if r.format == lenses::store::FORMAT {
                s.remember(r);
            }
        }
        super::refresh(&s.app);
        s.run(inbox, done_rx);
    });
}

impl Scheduler {
    fn remember(&mut self, r: &RunResult) {
        self.known.insert(r.id.clone(), r.ran_at);
        // Taken after the run, so a lens's own writes do not look like an edit.
        self.watched.insert(
            r.id.clone(),
            r.watch.iter().map(|p| (p.clone(), mtime(p))).collect(),
        );
    }

    fn run(&mut self, inbox: Receiver<Request>, done_rx: Receiver<RunResult>) {
        let store_path = paths::state_dir().join("findings.json");
        let mut store_mtime = mtime(&store_path);
        let mut config_mtime = mtime(&config::path());
        loop {
            match inbox.recv_timeout(Duration::from_secs(3)) {
                Ok(request) => self.handle(request),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            while let Ok(result) = done_rx.try_recv() {
                self.remember(&result);
                with_shared(&self.app, |sh| {
                    sh.running.remove(&result.id);
                    sh.results.insert(result.id.clone(), result);
                });
                super::refresh(&self.app);
            }
            if mtime(&store_path) != store_mtime {
                store_mtime = mtime(&store_path);
                self.pick_up_foreign_results();
            }
            let Some(cfg) = self.settings() else { continue };
            let settings_changed = mtime(&config::path()) != config_mtime;
            if settings_changed {
                config_mtime = mtime(&config::path());
            }
            self.launch_due(&cfg, settings_changed);
        }
    }

    /// The settings, or while the file is broken the last that loaded; the
    /// error is reported once per distinct problem.
    fn settings(&mut self) -> Option<Config> {
        match Config::load() {
            Ok(cfg) => {
                self.config_error = None;
                self.last_good = Some(cfg.clone());
                Some(cfg)
            }
            Err(e) => {
                let text = format!("{e:#}");
                if self.config_error.as_ref() != Some(&text) {
                    super::notify_error(&crate::i18n::t!("notify.badSettings", error = text));
                    self.config_error = Some(text);
                }
                self.last_good.clone()
            }
        }
    }

    fn running(&self) -> std::collections::BTreeSet<String> {
        self.app.state::<AppState>().lock().running.clone()
    }

    fn pick_up_foreign_results(&mut self) {
        let running = self.running();
        let mut changed = false;
        for (id, r) in lenses::store::load() {
            // Only newer results: an older one must never replace what is shown.
            if running.contains(&id) || self.known.get(&id).is_some_and(|k| *k >= r.ran_at) {
                continue;
            }
            self.remember(&r);
            with_shared(&self.app, |sh| {
                sh.results.insert(id, r);
            });
            changed = true;
        }
        if changed {
            super::refresh(&self.app);
        }
    }

    fn launch_due(&mut self, cfg: &Config, settings_changed: bool) {
        let running = self.running();
        let now = Utc::now();
        let mut started = Vec::new();
        for r in lenses::registry(cfg)
            .into_iter()
            .filter(|r| lenses::enabled(cfg, r))
        {
            let id = r.id().to_string();
            if running.contains(&id) {
                continue;
            }
            let forced = self.forced.remove(&id);
            let interval_due = lenses::is_due(cfg, &r, self.known.get(&id).copied(), now);
            let file_changed = self
                .watched
                .get(&id)
                .is_some_and(|files| files.iter().any(|(p, m)| mtime(p) != *m));
            if !(self.force_all
                || forced.is_some()
                || settings_changed
                || interval_due
                || file_changed)
            {
                continue;
            }
            let offline = forced.unwrap_or(false);
            let (cfg, done) = (cfg.clone(), self.done_tx.clone());
            started.push(id);
            thread::spawn(move || {
                let result = lenses::run(&cfg, &r, offline);
                log(&lenses::store::notify_new(&cfg, &result));
                if let Some(e) = &result.error {
                    log(&[format!("{} failed: {e}", result.title)]);
                }
                let _ = done.send(result);
            });
        }
        self.force_all = false;
        if !started.is_empty() {
            with_shared(&self.app, |sh| sh.running.extend(started));
            super::refresh(&self.app);
        }
    }

    fn handle(&mut self, request: Request) {
        match request {
            Request::CheckAll => self.force_all = true,
            Request::Run(ids, offline) => {
                self.forced.extend(ids.into_iter().map(|id| (id, offline)));
            }
            Request::ApplyAll => {
                match apply_all() {
                    Ok((done, failed)) if failed.is_empty() => super::toast(&self.app, done, true),
                    Ok((done, failed)) => {
                        let text = format!("{done}; failed: {}", failed.join("; "));
                        super::toast(&self.app, text.clone(), false);
                        super::notify_error(&text);
                    }
                    Err(e) => super::notify_error(&format!("{e:#}")),
                }
                self.force_all = true;
            }
            Request::Fix { lens, key } => self.fix(lens, key),
        }
    }

    /// Fix a finding on its own thread. The lens counts as running until the
    /// fix has re-run it, so the scheduler never starts it alongside.
    fn fix(&mut self, lens: String, key: String) {
        if self.running().contains(&lens) {
            super::toast(&self.app, crate::i18n::t!("toast.lensBusy"), false);
            return;
        }
        with_shared(&self.app, |sh| {
            sh.running.insert(lens.clone());
        });
        let (app, done_tx) = (self.app.clone(), self.done_tx.clone());
        thread::spawn(move || {
            match Config::load().and_then(|cfg| lenses::fix(&cfg, &lens, &key)) {
                Ok((done, result)) => {
                    log(std::slice::from_ref(&done));
                    super::toast(&app, done, true);
                    let _ = done_tx.send(result);
                }
                Err(e) => {
                    with_shared(&app, |sh| {
                        sh.running.remove(&lens);
                    });
                    super::refresh(&app);
                    super::toast(&app, format!("{e:#}"), false);
                    super::notify_error(&format!("{e:#}"));
                }
            }
        });
    }
}

/// Set every package manager to the cooldown: what changed, and what failed.
fn apply_all() -> Result<(String, Vec<String>)> {
    let cfg = Config::load()?;
    let outcomes = managers::apply_all(&cfg, &Ctx::new(&cfg), &[], Mode::Exact, false);
    let changed = outcomes
        .iter()
        .filter(|o| matches!(o.action, Action::Changed { .. }))
        .count();
    let failed = outcomes
        .iter()
        .filter_map(|o| match &o.action {
            Action::Failed { error } => Some(format!("{}: {error}", o.name)),
            _ => None,
        })
        .collect();
    Ok((
        crate::i18n::t!("toast.applied", count = changed, days = cfg.min_days),
        failed,
    ))
}
