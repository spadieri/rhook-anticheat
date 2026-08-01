// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Scan logging: console plus an optional transcript file.
//!
//! A detection tool that only prints verdicts is impossible to debug when
//! it says nothing -- you cannot tell "scanned and found nothing" apart
//! from "never scanned". Every stage therefore reports what it examined,
//! not only what it objected to, and `--verbose` adds the per-item detail
//! behind those counts.
//!
//! Output is deliberately ASCII-only: the transcript is meant to be read
//! back later, and a Windows console reading a UTF-8 file as ANSI turns
//! typographic dashes into mojibake.

use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::time::Instant;

/// Severity of a log record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Per-item detail. Printed to console only with `--verbose`, always
    /// written to the transcript file.
    Debug,
    /// Normal progress.
    Info,
    /// The scan could not complete a check -- a gap in coverage, not a
    /// clean result. Never rendered as "ok".
    Warn,
    /// A positive detection.
    Alert,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Debug => "dbg  ",
            Level::Info => "info ",
            Level::Warn => "WARN ",
            Level::Alert => "ALERT",
        }
    }
}

/// Console + file logger with elapsed-time stamps.
pub struct Log {
    start: Instant,
    verbose: bool,
    file: Option<File>,
    alerts: u32,
    warnings: u32,
}

impl Log {
    pub fn new(verbose: bool, path: Option<&str>) -> Self {
        let file = path.and_then(|p| match File::create(p) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("[!] cannot open transcript {p}: {e}");
                None
            }
        });
        Self {
            start: Instant::now(),
            verbose,
            file,
            alerts: 0,
            warnings: 0,
        }
    }

    pub fn line(&mut self, level: Level, msg: impl AsRef<str>) {
        match level {
            Level::Alert => self.alerts += 1,
            Level::Warn => self.warnings += 1,
            _ => {}
        }

        let elapsed = self.start.elapsed();
        let mut rendered = String::new();
        let _ = write!(
            rendered,
            "[{:>7.3}s] [{}] {}",
            elapsed.as_secs_f64(),
            level.tag(),
            msg.as_ref()
        );

        if level != Level::Debug || self.verbose {
            println!("{rendered}");
        }
        if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "{rendered}");
        }
    }

    pub fn debug(&mut self, msg: impl AsRef<str>) {
        self.line(Level::Debug, msg);
    }
    pub fn info(&mut self, msg: impl AsRef<str>) {
        self.line(Level::Info, msg);
    }
    pub fn warn(&mut self, msg: impl AsRef<str>) {
        self.line(Level::Warn, msg);
    }
    pub fn alert(&mut self, msg: impl AsRef<str>) {
        self.line(Level::Alert, msg);
    }

    /// Section divider -- makes a multi-pass transcript readable.
    pub fn section(&mut self, title: &str) {
        let bar = "-".repeat(60usize.saturating_sub(title.len() + 3));
        self.info(format!("-- {title} {bar}"));
    }

    pub fn alerts(&self) -> u32 {
        self.alerts
    }
    pub fn warnings(&self) -> u32 {
        self.warnings
    }
}
