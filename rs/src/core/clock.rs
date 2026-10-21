//! Time for PACT: a replaceable clock and the time rules of draft sections
//! 7.5 and 20.1, the validity window, the lifetimes, the presentation age and
//! the replay retention.
//!
//! Wire timestamps are integer seconds since the Unix epoch in
//! `0..=2^53-1`; instants are [`SystemTime`], compared exactly: a wire second
//! is never rounded to the precision of the clock.

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A source of the current time.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> SystemTime;
}

/// The system's wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock for tests: it stays where it is set.
#[derive(Debug)]
pub struct Fake {
    now: Mutex<SystemTime>,
}

impl Fake {
    /// A fake clock at `start`.
    pub fn new(start: SystemTime) -> Fake {
        Fake { now: Mutex::new(start) }
    }

    /// Moves the clock to `t`.
    pub fn set(&self, t: SystemTime) {
        *self.now.lock().unwrap_or_else(|e| e.into_inner()) = t;
    }

    /// Moves the clock forward by `d`.
    pub fn advance(&self, d: Duration) {
        let mut now = self.now.lock().unwrap_or_else(|e| e.into_inner());
        *now += d;
    }
}

impl Clock for Fake {
    fn now(&self) -> SystemTime {
        *self.now.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The largest clock skew the baseline allows (section 20.1).
pub const BASELINE_SKEW: Duration = Duration::from_secs(5);

const MAX_TIMESTAMP: i64 = (1 << 53) - 1;
const PRESENTATION_VALIDITY: Duration = Duration::from_secs(60);

/// Why a time check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// The skew is above [`BASELINE_SKEW`].
    Skew,
    /// A timestamp is outside `0..=9007199254740991`.
    Timestamp,
    /// `nbf` is later than now plus the skew.
    NotYetValid,
    /// `iat` is later than now plus the skew.
    IssuedInFuture,
    /// Now is not before `exp`.
    Expired,
    /// `exp` is not after `iat`, or the lifetime is above the artifact's
    /// maximum.
    Lifetime,
    /// The presentation was issued more than 60 seconds ago.
    TooOld,
}

impl Kind {
    fn message(self) -> &'static str {
        match self {
            Kind::Skew => "clock: skew must be between 0 and 5s",
            Kind::Timestamp => "clock: timestamp outside 0..9007199254740991",
            Kind::NotYetValid => "clock: not yet valid (nbf is in the future)",
            Kind::IssuedInFuture => "clock: issued in the future (iat is later than now plus skew)",
            Kind::Expired => "clock: expired",
            Kind::Lifetime => "clock: invalid lifetime",
            Kind::TooOld => "clock: presentation issued more than 60s ago",
        }
    }
}

/// A failed time check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: Kind,
    pub detail: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.message(), self.detail)
    }
}

impl std::error::Error for Error {}

fn fail(kind: Kind, detail: String) -> Error {
    Error { kind, detail }
}

/// The artifact types whose lifetimes section 20.1 bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Artifact {
    Presentation,
    Contract,
    Evidence,
    Snapshot,
    Outcome,
    Profile,
}

impl fmt::Display for Artifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Artifact::Presentation => "presentation",
            Artifact::Contract => "requirement contract",
            Artifact::Evidence => "evidence",
            Artifact::Snapshot => "reputation snapshot",
            Artifact::Outcome => "outcome report",
            Artifact::Profile => "profile",
        })
    }
}

/// The longest lifetime, `exp - iat`, of an artifact (section 20.1).
pub fn max_lifetime(a: Artifact) -> Duration {
    Duration::from_secs(match a {
        Artifact::Presentation | Artifact::Contract => 60,
        Artifact::Evidence => 3600,
        Artifact::Snapshot | Artifact::Outcome => 300,
        Artifact::Profile => 86400,
    })
}

fn check_skew(skew: Duration) -> Result<(), Error> {
    if skew > BASELINE_SKEW {
        return Err(fail(Kind::Skew, format!("got {skew:?}")));
    }
    Ok(())
}

fn check_range(name: &str, sec: i64) -> Result<(), Error> {
    if !(0..=MAX_TIMESTAMP).contains(&sec) {
        return Err(fail(Kind::Timestamp, format!("{name} is {sec}")));
    }
    Ok(())
}

const NANOS_PER_SEC: i128 = 1_000_000_000;

/// Nanoseconds since the Unix epoch of `t`, negative before it. Every
/// comparison of this module is made on this count and on wire seconds
/// scaled to it, never by adding a duration to a `SystemTime`: the range and
/// resolution of `SystemTime` depend on the platform (on Windows it counts
/// 100 ns intervals from 1601 and ends in the year 30828, far short of
/// 2^53-1 seconds), while an `i128` holds every wire second and every
/// instant exactly.
fn nanos(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

/// A wire second as nanoseconds since the epoch.
fn sec_nanos(sec: i64) -> i128 {
    i128::from(sec) * NANOS_PER_SEC
}

fn dur_nanos(d: Duration) -> i128 {
    d.as_nanos() as i128
}

/// Whole seconds since the epoch of `t`, floored, for messages.
fn unix(t: SystemTime) -> i128 {
    nanos(t).div_euclid(NANOS_PER_SEC)
}

/// The latest instant the platform's `SystemTime` can hold.
fn latest_system_time() -> SystemTime {
    let (mut lo, mut hi) = (0u64, u64::MAX);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if UNIX_EPOCH.checked_add(Duration::from_secs(mid)).is_some() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let base = UNIX_EPOCH + Duration::from_secs(lo);
    let (mut lo, mut hi) = (0u32, 999_999_999u32);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if base.checked_add(Duration::from_nanos(u64::from(mid))).is_some() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    base + Duration::from_nanos(u64::from(lo))
}

/// The instant `n` nanoseconds after the epoch (`n` >= 0), or the latest
/// instant the platform can hold when it is beyond that.
fn saturating_instant(n: i128) -> SystemTime {
    let d = Duration::new((n / NANOS_PER_SEC) as u64, (n % NANOS_PER_SEC) as u32);
    UNIX_EPOCH.checked_add(d).unwrap_or_else(latest_system_time)
}

/// Checks the validity window of a signed artifact at `now` (section 7.5):
/// every timestamp in range, `nbf` and `iat` no later than now plus `skew`,
/// and now before `exp`. `skew` is at most [`BASELINE_SKEW`].
pub fn check_window(iat: i64, nbf: i64, exp: i64, now: SystemTime, skew: Duration) -> Result<(), Error> {
    check_skew(skew)?;
    for (name, sec) in [("iat", iat), ("nbf", nbf), ("exp", exp)] {
        check_range(name, sec)?;
    }
    let now_ns = nanos(now);
    let latest = now_ns + dur_nanos(skew);
    if sec_nanos(nbf) > latest {
        return Err(fail(Kind::NotYetValid, format!("nbf {nbf}, now {}, skew {skew:?}", unix(now))));
    }
    if sec_nanos(iat) > latest {
        return Err(fail(Kind::IssuedInFuture, format!("iat {iat}, now {}, skew {skew:?}", unix(now))));
    }
    if now_ns >= sec_nanos(exp) {
        return Err(fail(Kind::Expired, format!("exp {exp}, now {}", unix(now))));
    }
    Ok(())
}

/// Checks that `exp` is after `iat` and that the lifetime is at most
/// [`max_lifetime`] of `a`.
pub fn check_lifetime(a: Artifact, iat: i64, exp: i64) -> Result<(), Error> {
    if exp <= iat {
        return Err(fail(Kind::Lifetime, format!("{a} exp {exp} is not after iat {iat}")));
    }
    let span = i128::from(exp) - i128::from(iat);
    let max = i128::from(max_lifetime(a).as_secs());
    if span > max {
        return Err(fail(Kind::Lifetime, format!("{a} lives {span} s, at most {max} s")));
    }
    Ok(())
}

/// Checks that a presentation issued at `iat` is at most 60 seconds old at
/// `now`.
pub fn check_presentation_age(iat: i64, now: SystemTime) -> Result<(), Error> {
    check_range("iat", iat)?;
    if nanos(now) > sec_nanos(iat) + dur_nanos(PRESENTATION_VALIDITY) {
        return Err(fail(Kind::TooOld, format!("iat {iat}, now {}", unix(now))));
    }
    Ok(())
}

/// The checks of a presentation: [`check_window`], [`check_lifetime`] and
/// [`check_presentation_age`].
pub fn check_presentation(iat: i64, nbf: i64, exp: i64, now: SystemTime, skew: Duration) -> Result<(), Error> {
    check_window(iat, nbf, exp, now, skew)?;
    check_lifetime(Artifact::Presentation, iat, exp)?;
    check_presentation_age(iat, now)
}

/// How long a replay cache keeps a presentation's `jti`: until the later of
/// its `exp` and `iat` plus 60 seconds plus the skew. Timestamps out of range
/// are clamped to it. An instant later than the platform's `SystemTime` can
/// hold is the latest one it can hold (on Windows, the year 30828).
pub fn replay_retention(exp: i64, iat: i64, skew: Duration) -> SystemTime {
    let clamp = |sec: i64| sec_nanos(sec.clamp(0, MAX_TIMESTAMP));
    let expiry = clamp(exp);
    let horizon = clamp(iat) + dur_nanos(PRESENTATION_VALIDITY) + dur_nanos(skew);
    saturating_instant(expiry.max(horizon))
}
