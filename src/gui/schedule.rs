//! Decide what is due every few seconds and run each due lens on its own
//! thread, so a slow one never holds up the others: interval elapsed, a file
//! it watches changed, the settings changed, or someone asked. Results
//! recorded by other processes (`lenstica check`) are picked up too.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use chrono::{DateTime, Utc};
use tauri::{AppHandle, Manager};

use super::{AppState, Request};
use crate::config::{self, Config};
use crate::lenses::{self, store::RunResult};
use crate::managers::{self, Ctx, Mode};
use crate::paths;

fn mtime(path: &PathBuf) -> Option<SystemTime> {
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
    let mut shared = state.shared.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut shared);
}

struct Scheduler {
    app: AppHandle,
    done_tx: Sender<RunResult>,
    last_run: HashMap<String, Instant>,
    watched: HashMap<String, Vec<(PathBuf, Option<SystemTime>)>>,
    known: HashMap<String, DateTime<Utc>>,
    /// Lenses asked for explicitly, with whether to stay offline.
    forced: BTreeMap<String, bool>,
    force_all: bool,
}

pub fn start(app: AppHandle, inbox: Receiver<Request>) {
    thread::spawn(move || {
        let (done_tx, done_rx) = mpsc::channel();
        let mut s = Scheduler {
            app,
            done_tx,
            last_run: HashMap::new(),
            watched: HashMap::new(),
            known: HashMap::new(),
            forced: BTreeMap::new(),
            force_all: false,
        };
        // Results already on disk count as runs, so a restart does not redo everything at once.
        for r in lenses::store::load().values() {
            s.remember(r, Some(r.ran_at));
        }
        super::refresh(&s.app);
        s.run(inbox, done_rx);
    });
}

impl Scheduler {
    fn remember(&mut self, r: &RunResult, ran_at: Option<DateTime<Utc>>) {
        let at = ran_at
            .and_then(|t| (Utc::now() - t).to_std().ok())
            .and_then(|age| Instant::now().checked_sub(age))
            .unwrap_or_else(Instant::now);
        self.last_run.insert(r.id.clone(), at);
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
                self.remember(&result, None);
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
            let Ok(cfg) = Config::load() else { continue };
            let settings_changed = mtime(&config::path()) != config_mtime;
            if settings_changed {
                config_mtime = mtime(&config::path());
            }
            self.launch_due(&cfg, settings_changed);
        }
    }

    fn pick_up_foreign_results(&mut self) {
        let running = {
            let state = self.app.state::<AppState>();
            let shared = state.shared.lock().unwrap_or_else(|p| p.into_inner());
            shared.running.clone()
        };
        let mut changed = false;
        for (id, r) in lenses::store::load() {
            if running.contains(&id) || self.known.get(&id) == Some(&r.ran_at) {
                continue;
            }
            self.remember(&r, None);
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
        let running = {
            let state = self.app.state::<AppState>();
            let shared = state.shared.lock().unwrap_or_else(|p| p.into_inner());
            shared.running.clone()
        };
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
            let interval_due = self
                .last_run
                .get(&id)
                .is_none_or(|t| t.elapsed() >= lenses::interval(cfg, &r));
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
                self.forced.extend(ids.into_iter().map(|id| (id, offline)))
            }
            Request::ApplyAll => {
                let outcome = (|| -> Result<String> {
                    let cfg = Config::load()?;
                    let outcomes =
                        managers::apply_all(&cfg, &Ctx::new(&cfg), &[], Mode::Exact, false);
                    let changed = outcomes
                        .iter()
                        .filter(|o| matches!(o.action, managers::Action::Changed { .. }))
                        .count();
                    Ok(format!(
                        "{changed} package managers set to {} days",
                        cfg.min_days
                    ))
                })();
                match outcome {
                    Ok(done) => super::toast(&self.app, done, true),
                    Err(e) => super::notify_error(&format!("{e:#}")),
                }
                self.force_all = true;
            }
            Request::Fix { lens, key } => {
                let app = self.app.clone();
                thread::spawn(move || {
                    match Config::load().and_then(|cfg| lenses::fix(&cfg, &lens, &key)) {
                        Ok(done) => {
                            log(std::slice::from_ref(&done));
                            super::toast(&app, done, true);
                        }
                        Err(e) => {
                            super::toast(&app, format!("{e:#}"), false);
                            super::notify_error(&format!("{e:#}"));
                        }
                    }
                });
            }
        }
    }
}
