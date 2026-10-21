//! core::clock, after go/core/clock/clock_test.go and window_test.go.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hop_top_pact::core::clock::{self, Artifact, Clock, Fake, Kind, SystemClock};

const T: i64 = 1_800_000_000;

/// The finest step every platform's `SystemTime` keeps: Windows counts
/// 100 ns intervals, so a smaller sub-second part would be lost there.
const TICK: u32 = 100;

/// The largest wire timestamp, 2^53-1 seconds.
const MAX_TS: i64 = (1 << 53) - 1;

fn at(sec: i64, nanos: u32) -> SystemTime {
    UNIX_EPOCH + Duration::new(sec as u64, nanos)
}

fn kind(r: Result<(), clock::Error>) -> Option<Kind> {
    r.err().map(|e| e.kind)
}

#[test]
fn lifetimes_and_skew_match_the_draft() {
    for (a, secs) in [
        (Artifact::Presentation, 60),
        (Artifact::Contract, 60),
        (Artifact::Evidence, 3600),
        (Artifact::Snapshot, 300),
        (Artifact::Outcome, 300),
        (Artifact::Profile, 86400),
    ] {
        assert_eq!(clock::max_lifetime(a), Duration::from_secs(secs), "{a}");
    }
    assert_eq!(clock::BASELINE_SKEW, Duration::from_secs(5));
}

#[test]
fn check_window() {
    let s = clock::BASELINE_SKEW;
    let now = at(T, 0);
    assert_eq!(kind(clock::check_window(T, T, T + 60, now, s)), None);
    assert_eq!(kind(clock::check_window(T + 5, T + 5, T + 60, now, s)), None, "skew allows 5 s");
    assert_eq!(kind(clock::check_window(T, T + 6, T + 60, now, s)), Some(Kind::NotYetValid));
    assert_eq!(kind(clock::check_window(T + 6, T, T + 60, now, s)), Some(Kind::IssuedInFuture));
    assert_eq!(kind(clock::check_window(T - 60, T - 60, T, now, s)), Some(Kind::Expired), "exp is exclusive");
    assert_eq!(kind(clock::check_window(T - 60, T - 60, T, at(T - 1, 1_000_000_000 - TICK), s)), None);
    assert_eq!(
        kind(clock::check_window(T, T, T + 1, at(T, 1_000_000_000 - TICK), s)),
        None,
        "sub-second now before exp"
    );
    assert_eq!(kind(clock::check_window(T, T + 5, T + 60, at(T, 0), s)), None, "nbf exactly now plus skew");
    assert_eq!(kind(clock::check_window(T, T + 6, T + 60, at(T, 1_000_000_000 - TICK), s)), Some(Kind::NotYetValid));
    assert_eq!(kind(clock::check_window(T, T + 6, T + 60, at(T + 1, 0), s)), None);
    assert_eq!(kind(clock::check_window(-1, T, T + 60, now, s)), Some(Kind::Timestamp));
    assert_eq!(kind(clock::check_window(T, T, 1 << 53, now, s)), Some(Kind::Timestamp));
    assert_eq!(kind(clock::check_window(T, T, T + 60, now, Duration::from_millis(5001))), Some(Kind::Skew));
}

#[test]
fn check_lifetime() {
    assert_eq!(kind(clock::check_lifetime(Artifact::Presentation, T, T + 60)), None);
    assert_eq!(kind(clock::check_lifetime(Artifact::Presentation, T, T + 61)), Some(Kind::Lifetime));
    assert_eq!(kind(clock::check_lifetime(Artifact::Evidence, T, T)), Some(Kind::Lifetime));
    assert_eq!(kind(clock::check_lifetime(Artifact::Profile, 0, 86400)), None);
    assert_eq!(kind(clock::check_lifetime(Artifact::Profile, i64::MIN, i64::MAX)), Some(Kind::Lifetime));
}

#[test]
fn check_presentation_age() {
    assert_eq!(kind(clock::check_presentation_age(T, at(T + 60, 0))), None);
    assert_eq!(kind(clock::check_presentation_age(T, at(T + 60, TICK))), Some(Kind::TooOld), "one tick past 60 s");
    assert_eq!(kind(clock::check_presentation_age(-5, at(T, 0))), Some(Kind::Timestamp));
    assert_eq!(kind(clock::check_presentation(T, T, T + 60, at(T + 30, 0), clock::BASELINE_SKEW)), None);
    assert_eq!(
        kind(clock::check_presentation(T, T, T + 61, at(T + 30, 0), clock::BASELINE_SKEW)),
        Some(Kind::Lifetime)
    );
}

#[test]
fn timestamps_at_the_end_of_the_range() {
    let s = clock::BASELINE_SKEW;
    let now = at(T, 0);
    assert_eq!(kind(clock::check_window(T, T, MAX_TS, now, s)), None);
    assert_eq!(kind(clock::check_window(T, MAX_TS, MAX_TS, now, s)), Some(Kind::NotYetValid));
    assert_eq!(kind(clock::check_window(MAX_TS, T, MAX_TS, now, s)), Some(Kind::IssuedInFuture));
    assert_eq!(kind(clock::check_presentation_age(MAX_TS, now)), None);
    assert_eq!(kind(clock::check_presentation_age(0, now)), Some(Kind::TooOld));
    let before_epoch = UNIX_EPOCH - Duration::from_secs(10);
    assert_eq!(kind(clock::check_window(0, 0, 1, before_epoch, s)), Some(Kind::NotYetValid));
    assert_eq!(kind(clock::check_window(0, 0, 1, before_epoch + Duration::from_secs(4), s)), Some(Kind::NotYetValid));
    assert_eq!(kind(clock::check_window(0, 0, 1, before_epoch + Duration::from_secs(5), s)), None);
}

#[test]
fn replay_retention() {
    let s = clock::BASELINE_SKEW;
    assert_eq!(clock::replay_retention(T + 60, T, s), at(T + 65, 0));
    assert_eq!(clock::replay_retention(T + 600, T, s), at(T + 600, 0));
    assert_eq!(clock::replay_retention(-1, -1, Duration::ZERO), at(60, 0));
    // 2^53-1 seconds is past the end of SystemTime on Windows (year 30828):
    // there the result is the latest instant the platform holds.
    let got = clock::replay_retention(i64::MAX, 0, s);
    match UNIX_EPOCH.checked_add(Duration::from_secs(MAX_TS as u64)) {
        Some(max) => assert_eq!(got, max),
        None => {
            assert!(got > at(T, 0));
            assert!(
                got.checked_add(Duration::from_nanos(u64::from(TICK))).is_none(),
                "{got:?} is not the latest instant"
            );
        }
    }
}

#[test]
fn clocks() {
    let before = SystemTime::now();
    let t = SystemClock.now();
    assert!(t >= before && t <= SystemTime::now());
    let f = Arc::new(Fake::new(at(T, 0)));
    f.advance(Duration::from_millis(1500));
    assert_eq!(f.now(), at(T + 1, 500_000_000));
    f.set(at(5, 0));
    assert_eq!(f.now(), at(5, 0));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let f = f.clone();
            std::thread::spawn(move || {
                for _ in 0..100 {
                    f.advance(Duration::from_secs(1));
                    let _ = f.now();
                }
            })
        })
        .collect();
    threads.into_iter().for_each(|h| h.join().unwrap());
    assert_eq!(f.now(), at(805, 0));
}
