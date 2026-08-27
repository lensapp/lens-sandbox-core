//! Run a set of scripts inside the cage before the workload starts.
//!
//! The point of running them here, rather than while the sandbox is being
//! built, is that a script reaches exactly what the workload will reach:
//! the network policy is already in force, so a script that fetches a
//! package is governed by the same rules and can raise the same
//! decisions. What it cannot do is start earlier and find the network
//! open.
//!
//! This module owns two things and deliberately not a third. It resolves
//! a whole set of identities at once, so a set naming an identity the
//! image lacks can fail before anything has run; and it runs a whole set
//! in order, stopping at the first failure. Both take a set rather than a
//! single script for that reason — a caller that interleaves them one
//! script at a time gets neither guarantee, and nothing here can stop it.
//!
//! It does not own what happens next. A caller decides whether a failure
//! aborts the workload, and with what status, because only the caller
//! knows what a workload is.

use std::process::Stdio;

use async_trait::async_trait;
use tokio::process::Command;

use crate::activity::ActivityStream;
use crate::child_spawner::{ChildSpec, build_command};
use crate::privilege::{Passwd, SandboxCredentials};

/// One script to run, as the caller staged it.
///
/// Deliberately carries no `serde` derives: how a script reaches the
/// guest is the caller's format to own and version, and a shared
/// serialized shape would couple two products to one wire contract for
/// the sake of three fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreStartStep {
    /// Where the script is, as a path the guest can execute.
    pub script: String,
    /// Who runs it, as a `USER[:GROUP]` resolved inside the guest.
    /// `None` means the workload's own identity.
    pub user: Option<String>,
    /// How a failure and the console name this script. A script has no
    /// name of its own, so the caller supplies one.
    pub label: String,
}

/// One script whose identity has been resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStep {
    pub label: String,
    pub script: String,
    /// `None` keeps the caller's own identity, which is what a step
    /// declaring no user asked for.
    pub creds: Option<SandboxCredentials>,
}

/// One script ready to spawn.
///
/// The caller builds this from a [`ResolvedStep`], because the env a
/// script gets depends on the identity that runs it and only the caller
/// knows how its own env is layered.
pub struct PreparedScript {
    pub label: String,
    pub spec: ChildSpec,
}

/// Why a set of scripts did not complete.
///
/// The variants carry fields rather than a formatted sentence: a caller
/// reports these in its own vocabulary, and only it knows what a failure
/// means for whatever was going to run afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreStartFailure {
    /// An identity the image cannot resolve. Raised before any script
    /// runs.
    UnresolvableUser {
        label: String,
        user: String,
        reason: String,
    },
    /// A script that could not be started at all.
    Spawn {
        label: String,
        position: String,
        reason: String,
    },
    /// A script that ran and failed.
    Exit {
        label: String,
        position: String,
        code: i32,
    },
}

impl std::fmt::Display for PreStartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreStartFailure::UnresolvableUser {
                label,
                user,
                reason,
            } => write!(
                f,
                "pre-start script {label:?} asks to run as {user:?}, which this sandbox cannot resolve: {reason}"
            ),
            PreStartFailure::Spawn {
                label,
                position,
                reason,
            } => write!(
                f,
                "pre-start script {position} ({label:?}) could not start: {reason}"
            ),
            PreStartFailure::Exit {
                label,
                position,
                code,
            } => write!(
                f,
                "pre-start script {position} ({label:?}) exited with code {code}"
            ),
        }
    }
}

impl std::error::Error for PreStartFailure {}

/// Spawns one prepared script and reports the status it exited with.
///
/// A port because how output reaches a person differs per caller: one
/// streams it to an attached console, another collects it for a log.
///
/// The `Command` arrives built and with fd 0 already settled, rather than
/// as the spec it came from. An implementation that built its own would
/// reinherit the caller's stdin, which is the hang this module exists to
/// prevent, and no test of the implementation would notice. Stdout and
/// stderr are untouched, which is the whole of what a runner chooses.
#[async_trait]
pub trait StepRunner: Send + Sync {
    async fn run(
        &self,
        command: Command,
        label: &str,
        position: &str,
        activity: ActivityStream,
    ) -> Result<i32, String>;
}

/// Resolve every script's identity before any of them runs.
///
/// All or nothing on purpose: a set that names an identity the image
/// lacks fails while nothing has happened yet, rather than half-way
/// through and with the earlier scripts' changes already applied.
pub fn resolve_steps(
    steps: &[PreStartStep],
    own_creds: Option<&SandboxCredentials>,
    passwd: &dyn Passwd,
) -> Result<Vec<ResolvedStep>, PreStartFailure> {
    steps
        .iter()
        .map(|step| resolve_one(step, own_creds, passwd))
        .collect()
}

fn resolve_one(
    step: &PreStartStep,
    own_creds: Option<&SandboxCredentials>,
    passwd: &dyn Passwd,
) -> Result<ResolvedStep, PreStartFailure> {
    let creds = match &step.user {
        None => own_creds.cloned(),
        Some(user) => Some(SandboxCredentials::resolve_user_spec(user, passwd).map_err(
            |reason| PreStartFailure::UnresolvableUser {
                label: step.label.clone(),
                user: user.clone(),
                reason,
            },
        )?),
    };
    Ok(ResolvedStep {
        label: step.label.clone(),
        script: step.script.clone(),
        creds,
    })
}

/// Where a script runs.
///
/// The identity's own home, so a script writing to `$HOME` writes
/// somewhere that identity owns. Falls back to `/`, which every image
/// has — note that a numeric identity with no passwd line has no home to
/// offer, so it lands there too.
///
/// A caller whose workload runs somewhere else should not reuse that
/// directory here: it may be a mount the script exists to prepare, which
/// is not a place to be standing while preparing it.
pub fn script_cwd(creds: Option<&SandboxCredentials>) -> String {
    creds
        .map(SandboxCredentials::home)
        .filter(|home| !home.is_empty())
        .unwrap_or("/")
        .to_string()
}

/// The hardened `Command` for one prepared script, reading no stdin.
///
/// A script gets `/dev/null` on fd 0. The caller's own stdin belongs to
/// whoever attached to the run, and nobody answers it before the
/// workload starts; nothing bounds a script with a timeout either, so a
/// tool that stops to ask a question holds the boot open for good — and
/// a quiet tool gives no clue that it did.
///
/// Private, and called by [`run_all`] rather than by a [`StepRunner`],
/// so that fd 0 is a rule and not a convention an implementation has to
/// remember.
fn script_command(script: &PreparedScript) -> Command {
    let mut cmd = build_command(&script.spec);
    cmd.stdin(Stdio::null());
    cmd
}

/// Run every script in order, stopping at the first that fails.
///
/// Each script's position is reported as `n/total`, since a script has no
/// name a reader would recognise and several may share a label.
pub async fn run_all(
    scripts: &[PreparedScript],
    runner: &dyn StepRunner,
    activity: &ActivityStream,
) -> Result<(), PreStartFailure> {
    let total = scripts.len();
    for (index, script) in scripts.iter().enumerate() {
        let position = format!("{}/{total}", index + 1);
        let command = script_command(script);
        match runner
            .run(command, &script.label, &position, activity.clone())
            .await
        {
            Err(reason) => {
                return Err(PreStartFailure::Spawn {
                    label: script.label.clone(),
                    position,
                    reason,
                });
            }
            Ok(0) => {}
            Ok(code) => {
                return Err(PreStartFailure::Exit {
                    label: script.label.clone(),
                    position,
                    code,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::fd::{AsFd, OwnedFd};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeRunner {
        /// What each call answers, in order; a missing entry answers
        /// success.
        answers: Mutex<Vec<Result<i32, String>>>,
        seen: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl StepRunner for FakeRunner {
        async fn run(
            &self,
            _command: Command,
            label: &str,
            position: &str,
            _activity: ActivityStream,
        ) -> Result<i32, String> {
            self.seen
                .lock()
                .expect("the fake's log is uncontended")
                .push(format!("{position} {label}"));
            let mut answers = self
                .answers
                .lock()
                .expect("the fake's answers are uncontended");
            if answers.is_empty() {
                return Ok(0);
            }
            answers.remove(0)
        }
    }

    #[derive(Default)]
    struct FakePasswd {
        users: Vec<(&'static str, u32, u32)>,
    }

    impl Passwd for FakePasswd {
        fn uid_of(&self, name: &str) -> Option<u32> {
            self.users
                .iter()
                .find(|(n, ..)| *n == name)
                .map(|(_, uid, _)| *uid)
        }
        fn primary_gid_of(&self, name: &str) -> Option<u32> {
            self.users
                .iter()
                .find(|(n, ..)| *n == name)
                .map(|(.., gid)| *gid)
        }
        fn gid_of_group(&self, _group: &str) -> Option<u32> {
            None
        }
    }

    fn image() -> FakePasswd {
        FakePasswd {
            users: vec![("node", 1000, 20)],
        }
    }

    fn step(label: &str, user: Option<&str>) -> PreStartStep {
        PreStartStep {
            script: format!("/scripts/{label}.sh"),
            user: user.map(str::to_string),
            label: label.to_string(),
        }
    }

    fn prepared(labels: &[&str]) -> Vec<PreparedScript> {
        labels
            .iter()
            .map(|label| PreparedScript {
                label: (*label).to_string(),
                spec: ChildSpec {
                    argv: vec!["sh".into(), "-e".into(), "/scripts/one.sh".into()],
                    cwd: None,
                    env: HashMap::new(),
                    creds: None,
                    is_root: false,
                },
            })
            .collect()
    }

    async fn run(scripts: &[PreparedScript], runner: &FakeRunner) -> Result<(), PreStartFailure> {
        run_all(scripts, runner, &ActivityStream::new()).await
    }

    fn uid_of(resolved: &ResolvedStep) -> Option<u32> {
        resolved
            .creds
            .as_ref()
            .map(|creds| creds.uid_gid().0.as_raw())
    }

    #[tokio::test]
    async fn the_scripts_run_in_order_each_named_by_its_position() {
        let runner = FakeRunner::default();
        run(&prepared(&["install psql", "seed the cache"]), &runner)
            .await
            .expect("both succeed");
        assert_eq!(
            *runner.seen.lock().expect("uncontended"),
            ["1/2 install psql", "2/2 seed the cache"],
            "the order is the caller's order, and the position is what tells a reader which of several scripts they are watching"
        );
    }

    #[tokio::test]
    async fn a_script_that_exits_non_zero_stops_the_sequence() {
        let runner = FakeRunner {
            answers: Mutex::new(vec![Ok(100)]),
            ..Default::default()
        };
        let failure = run(&prepared(&["install psql", "seed the cache"]), &runner)
            .await
            .expect_err("a failing script ends the sequence");
        assert_eq!(
            failure,
            PreStartFailure::Exit {
                label: "install psql".into(),
                position: "1/2".into(),
                code: 100,
            }
        );
        assert_eq!(
            runner.seen.lock().expect("uncontended").len(),
            1,
            "a later script would run against an environment the failed one never finished preparing"
        );
    }

    #[tokio::test]
    async fn a_script_that_cannot_start_is_reported_with_the_reason() {
        let runner = FakeRunner {
            answers: Mutex::new(vec![Err("No such file or directory".into())]),
            ..Default::default()
        };
        let failure = run(&prepared(&["install psql"]), &runner)
            .await
            .expect_err("a script that cannot start ends the sequence");
        assert_eq!(
            failure,
            PreStartFailure::Spawn {
                label: "install psql".into(),
                position: "1/1".into(),
                reason: "No such file or directory".into(),
            },
            "an image shipping no sh fails here, and the reason is the only thing that tells the author why"
        );
    }

    #[tokio::test]
    async fn no_scripts_runs_nothing_and_succeeds() {
        let runner = FakeRunner::default();
        run(&[], &runner).await.expect("nothing to do succeeds");
        assert!(
            runner.seen.lock().expect("uncontended").is_empty(),
            "a caller that stages none must reach whatever comes next exactly as it did before this existed"
        );
    }

    #[test]
    fn a_script_naming_no_user_takes_the_callers_own_identity() {
        let own = SandboxCredentials::resolve_by_uid(1000, 20).expect("resolves on a host");
        let resolved =
            resolve_steps(&[step("seed", None)], Some(&own), &image()).expect("nothing to resolve");
        assert_eq!(
            uid_of(&resolved[0]),
            Some(1000),
            "the default is whoever the caller already runs as, so a script that needs nothing special needs to say nothing"
        );
    }

    #[test]
    fn a_script_naming_a_user_resolves_it_against_the_image() {
        // Distinct from `node`'s 1000:20, or the two steps' credentials
        // would compare equal and the assertion could not tell which
        // identity each one got.
        let own = SandboxCredentials::resolve_by_uid(1001, 21).expect("resolves on a host");
        let node = SandboxCredentials::resolve_user_spec("node", &image()).expect("node resolves");

        let resolved = resolve_steps(
            &[step("install", Some("node")), step("seed", None)],
            Some(&own),
            &image(),
        )
        .expect("both resolve");

        assert_eq!(
            resolved,
            vec![
                ResolvedStep {
                    label: "install".into(),
                    script: "/scripts/install.sh".into(),
                    creds: Some(node),
                },
                ResolvedStep {
                    label: "seed".into(),
                    script: "/scripts/seed.sh".into(),
                    creds: Some(own),
                },
            ],
            "the caller turns `script` into argv and shows `label` to a person, so the two must not trade places, and the order is the order the caller asked for"
        );
    }

    #[test]
    fn a_caller_with_no_identity_of_its_own_leaves_a_defaulting_script_alone() {
        let resolved =
            resolve_steps(&[step("seed", None)], None, &image()).expect("nothing to resolve");
        assert_eq!(
            uid_of(&resolved[0]),
            None,
            "there is no identity to inherit, so the script runs as the caller does — inventing one here would be inventing a privilege level"
        );
    }

    #[test]
    fn a_user_the_image_cannot_resolve_fails_before_any_script_runs() {
        let failure = resolve_steps(
            &[step("first", None), step("second", Some("ghosts"))],
            None,
            &image(),
        )
        .expect_err("an identity this image lacks has no answer");
        assert_eq!(
            failure,
            PreStartFailure::UnresolvableUser {
                label: "second".into(),
                user: "ghosts".into(),
                reason: "no user \"ghosts\" in passwd".into(),
            },
            "resolving is all-or-nothing so that a set naming a missing identity fails while nothing has happened yet, rather than after the first script already changed the guest"
        );
    }

    #[test]
    fn every_failure_names_the_script_and_what_became_of_it() {
        let cases = [
            (
                PreStartFailure::UnresolvableUser {
                    label: "install psql".into(),
                    user: "postgres".into(),
                    reason: "no user \"postgres\" in passwd".into(),
                },
                "cannot resolve",
            ),
            (
                PreStartFailure::Spawn {
                    label: "install psql".into(),
                    position: "1/2".into(),
                    reason: "No such file or directory".into(),
                },
                "could not start",
            ),
            (
                PreStartFailure::Exit {
                    label: "install psql".into(),
                    position: "1/2".into(),
                    code: 100,
                },
                "exited with code 100",
            ),
        ];
        for (failure, outcome) in cases {
            let message = failure.to_string();
            assert!(
                message.contains("install psql") && message.contains(outcome),
                "a reader has to learn which script failed and what became of it from one line, without this module claiming to know what ran afterwards; got: {message}"
            );
        }
    }

    #[test]
    fn a_script_runs_in_its_own_identitys_home() {
        let creds = SandboxCredentials::resolve_by_uid(0, 0).expect("root resolves everywhere");
        assert_eq!(
            script_cwd(Some(&creds)),
            creds.home(),
            "a script writing to $HOME has to land somewhere the identity running it owns"
        );
    }

    #[test]
    fn a_script_with_no_identity_or_no_home_runs_at_the_root() {
        assert_eq!(script_cwd(None), "/");
        let homeless =
            SandboxCredentials::resolve_by_uid(60002, 60002).expect("resolves on a host");
        assert_eq!(
            script_cwd(Some(&homeless)),
            "/",
            "a numeric identity with no passwd line has no home to offer, and every image has a root directory"
        );
    }

    fn reads_own_stdin() -> PreparedScript {
        PreparedScript {
            label: "install".into(),
            spec: ChildSpec {
                argv: vec!["sh".into(), "-c".into(), "readlink /proc/self/fd/0".into()],
                cwd: None,
                env: HashMap::new(),
                creds: None,
                is_root: false,
            },
        }
    }

    async fn fd_zero_of(mut cmd: Command) -> String {
        cmd.stdout(Stdio::piped());
        let out = cmd
            .spawn()
            .expect("sh should spawn")
            .wait_with_output()
            .await
            .expect("the child should be waitable");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// The most naive runner there is: it spawns exactly the `Command` it
    /// was handed and chooses nothing but stdout. What fd 0 says here is
    /// what `run_all` gave it, not what this implementation remembered.
    #[derive(Default)]
    struct ReportsFdZero(Mutex<Vec<String>>);

    #[async_trait]
    impl StepRunner for ReportsFdZero {
        async fn run(
            &self,
            command: Command,
            _label: &str,
            _position: &str,
            _activity: ActivityStream,
        ) -> Result<i32, String> {
            let reported = fd_zero_of(command).await;
            self.0
                .lock()
                .expect("the fake's log is uncontended")
                .push(reported);
            Ok(0)
        }
    }

    /// Holds a pipe on fd 0 of the test process until it is dropped.
    ///
    /// The assertion below is about what `run_all` wires, so the test
    /// process must not already read `/dev/null` itself — under
    /// `cargo test </dev/null` and on many CI runners it does, and a
    /// child that merely inherited fd 0 would then report the same thing
    /// a settled one does. With a pipe there, the two answers differ.
    ///
    /// Restoring fd 0 on drop keeps the swap invisible to the tests
    /// running beside this one. None of them read stdin; those that spawn
    /// a child inherit a pipe instead of a terminal for a moment, which
    /// no assertion of theirs looks at.
    ///
    /// Every fd the guard holds is close-on-exec, so only fd 0 itself
    /// crosses an `exec`. A child of some neighbouring test that kept the
    /// write end alive would hold the pipe open, and a later reader of fd
    /// 0 would wait for an EOF that never comes.
    struct StdinIsAPipe {
        saved: OwnedFd,
        _ends: (OwnedFd, OwnedFd),
    }

    impl StdinIsAPipe {
        fn install() -> Self {
            let saved = std::io::stdin()
                .as_fd()
                .try_clone_to_owned()
                .expect("fd 0 can be duplicated");
            let ends =
                nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("a pipe can be opened");
            nix::unistd::dup2_stdin(&ends.0).expect("fd 0 can be replaced");
            Self { saved, _ends: ends }
        }
    }

    impl Drop for StdinIsAPipe {
        fn drop(&mut self) {
            nix::unistd::dup2_stdin(&self.saved).expect("fd 0 can be restored");
        }
    }

    /// A script that reads fd 0 gets an EOF. On the caller's own stdin it
    /// would get a descriptor nobody answers before the workload starts,
    /// and no timeout would ever end the wait.
    ///
    /// Driven through `run_all` on purpose: the rule is only a rule if a
    /// runner that builds nothing itself still cannot reach the caller's
    /// stdin.
    #[tokio::test]
    async fn a_script_reads_no_stdin() {
        let _stdin = StdinIsAPipe::install();
        let runner = ReportsFdZero::default();
        run_all(&[reads_own_stdin()], &runner, &ActivityStream::new())
            .await
            .expect("the script succeeds");
        assert_eq!(
            *runner.0.lock().expect("uncontended"),
            ["/dev/null"],
            "a runner gets its stdin settled for it, so no implementation can hand a script the console nobody answers"
        );
    }

    /// The control: fd 0 reports what the parent wired, so the assertion
    /// above is about what `run_all` builds and not about what a child
    /// always says.
    #[tokio::test]
    async fn the_stdin_a_child_reports_is_the_one_it_was_given() {
        let script = reads_own_stdin();
        let mut cmd = build_command(&script.spec);
        cmd.stdin(Stdio::piped());
        assert!(fd_zero_of(cmd).await.starts_with("pipe:"));
    }
}
