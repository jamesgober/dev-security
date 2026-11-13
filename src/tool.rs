//! Locating and starting the external tools.
//!
//! `cargo audit` and `cargo deny` are external cargo subcommands, and a
//! `[alias]` in the audited tree's `.cargo/config.toml` takes precedence
//! over an external subcommand of the same name. Going through `cargo`
//! would let the audited tree replace the tool with a command of its
//! own, which would then run that tree's code. The binaries are started
//! directly instead, the same way cargo itself starts them:
//! `cargo-audit audit <args>` and `cargo-deny deny <args>`.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Absolute path of an installed cargo subcommand binary, such as
/// `cargo-audit`.
///
/// Looks in `$CARGO_HOME/bin` (by default `~/.cargo/bin`) first, then in
/// each directory on `PATH`, which is the order cargo uses. Relative
/// `PATH` entries are skipped, because the tools run with the audited
/// tree as their working directory.
pub(crate) fn resolve(binary: &str) -> Option<PathBuf> {
    let file = format!("{binary}{}", env::consts::EXE_SUFFIX);
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(home) = cargo_home() {
        dirs.push(home.join("bin"));
    }
    if let Some(path) = env::var_os("PATH") {
        dirs.extend(env::split_paths(&path));
    }
    dirs.into_iter()
        .filter(|d| d.is_absolute())
        .map(|d| d.join(&file))
        .find(|p| p.is_file())
}

/// A command that runs `binary` as cargo would run the `subcommand`
/// external subcommand: `<binary> <subcommand> <args>`.
pub(crate) fn command(binary: &Path, subcommand: &str) -> Command {
    let mut cmd = Command::new(binary);
    cmd.arg(subcommand);
    cmd
}

fn cargo_home() -> Option<PathBuf> {
    if let Some(home) = env::var_os("CARGO_HOME").filter(|h| !h.is_empty()) {
        return Some(PathBuf::from(home));
    }
    env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .or_else(|| env::var_os("USERPROFILE").filter(|h| !h.is_empty()))
        .map(|h| PathBuf::from(h).join(".cargo"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_is_not_resolved() {
        assert!(resolve("cargo-no-such-tool-for-dev-security").is_none());
    }

    #[test]
    fn command_runs_the_binary_not_cargo() {
        let bin = PathBuf::from(if cfg!(windows) {
            r"C:\tools\cargo-audit.exe"
        } else {
            "/opt/tools/cargo-audit"
        });
        let cmd = command(&bin, "audit");
        assert_eq!(cmd.get_program(), bin.as_os_str());
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, ["audit"]);
    }
}
