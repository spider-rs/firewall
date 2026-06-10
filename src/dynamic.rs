//! Runtime "discovered-bad" overlay — a lock-free feedback loop on top of the
//! static FST/PHF blocklists.
//!
//! The static lists ([`crate::is_url_bad`] et al.) are immutable and baked in at
//! build time. This module adds a *growable* overlay so the application can
//! teach the firewall about hosts it discovers are bad at runtime (a WAF /
//! challenge wall, repeated hard failures, a fresh-malicious host) — after which
//! every later lookup short-circuits locally with **no network round-trip**.
//!
//! Design (mirrors the consumers' batcher discipline):
//! - **Lock-free reads.** Lookups load an immutable [`arc_swap`] snapshot — one
//!   atomic pointer load, then a hash lookup. Zero contention with reporters,
//!   no `Mutex`.
//! - **Non-blocking reporters.** [`report_bad`] pushes into a lock-free
//!   [`crossbeam_queue::SegQueue`] and returns; it never blocks the caller.
//! - **No background runtime required.** Queued reports are folded into the
//!   snapshot by an *opportunistic, single-flight* merge that runs inline on a
//!   reporting thread (guarded by one `AtomicBool` CAS). No tokio, no thread is
//!   mandatory ([`enable_background_pruner`] is opt-in for timely reclamation).
//! - **TTL.** Entries expire after a configurable duration and are treated as
//!   absent the instant they elapse — correctness never depends on a merge
//!   having run. Expired entries are physically reclaimed at the next merge.
//! - **Fleet-share + durable capture.** [`set_report_sink`] hands every report
//!   to the host app (synchronously, borrowed) so it can broadcast to a shared
//!   store and/or persist the host for later promotion into the static maps.
//!   [`seed_dynamic`] re-loads such a list on boot.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use crossbeam_queue::SegQueue;

use crate::{get_host_from_url, CAT_BAD};

/// Overlay map keyed by host. Uses `foldhash` (fast, DoS-not-a-concern here —
/// keys are our own normalized hosts) so the read path's lookup is cheap on the
/// ultra-hot "allow" case where every legit host reaches this final OR-term.
type DynMap = HashMap<Box<str>, DynEntry, foldhash::fast::RandomState>;

#[inline]
fn new_map(cap: usize) -> DynMap {
    HashMap::with_capacity_and_hasher(cap, foldhash::fast::RandomState::default())
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Why a host was reported. Cheap, `Copy`, allocation-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BadReason {
    /// A post-fetch WAF / bot-challenge page was detected for this host.
    WafChallenge,
    /// The static firewall already blocked it (reinforcement / telemetry).
    FirewallBlock,
    /// Repeated hard fetch failures (timeouts / all tiers exhausted).
    HardFailures,
    /// Operator action or a fleet/seed import.
    Manual,
    /// Anything else.
    Other,
}

/// A single report handed to the sink. Borrowed — the crate allocates nothing
/// for the sink; the host app decides whether to clone/queue.
#[non_exhaustive]
pub struct BadReport<'a> {
    /// Normalized host (lowercased, scheme/path stripped).
    pub host: &'a str,
    /// Category bitmask (`CAT_BAD` etc.); never 0.
    pub cats: u64,
    /// Why it was reported.
    pub reason: BadReason,
    /// When it was reported.
    pub at: Instant,
    /// The effective TTL applied to this entry.
    pub ttl: Duration,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct DynEntry {
    cats: u64,
    expires: Instant,
}

struct DynSnapshot {
    map: DynMap,
    built: Instant,
}

struct PendingReport {
    host: Box<str>,
    cats: u64,
    expires: Instant,
}

type ReportSinkFn = dyn Fn(&BadReport) + Send + Sync + 'static;

/// The published, immutable overlay snapshot. `None` until the first report —
/// so the read path is a single `Option` check (free) until the overlay is used.
static SNAPSHOT: OnceLock<ArcSwap<DynSnapshot>> = OnceLock::new();
/// Lock-free multi-producer intake. Drained by the merge.
static QUEUE: OnceLock<SegQueue<PendingReport>> = OnceLock::new();
/// Number of reports queued but not yet merged.
static PENDING: AtomicUsize = AtomicUsize::new(0);
/// Single-flight guard: exactly one thread rebuilds the snapshot at a time.
static MERGE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
/// Host-supplied sink, set once.
static REPORT_SINK: OnceLock<Box<ReportSinkFn>> = OnceLock::new();
/// Idempotent guard for the optional pruner thread.
static PRUNER_STARTED: AtomicBool = AtomicBool::new(false);

// Tunables (atomics; no Mutex).
static DEFAULT_TTL_MS: AtomicU64 = AtomicU64::new(24 * 60 * 60 * 1000); // 24h
static MERGE_BATCH: AtomicUsize = AtomicUsize::new(64);
static MERGE_INTERVAL_MS: AtomicU64 = AtomicU64::new(5_000);
static MAX_ENTRIES: AtomicUsize = AtomicUsize::new(100_000);

#[inline]
fn snapshot_cell() -> &'static ArcSwap<DynSnapshot> {
    SNAPSHOT.get_or_init(|| {
        ArcSwap::from_pointee(DynSnapshot {
            map: new_map(0),
            built: Instant::now(),
        })
    })
}

#[inline]
fn queue() -> &'static SegQueue<PendingReport> {
    QUEUE.get_or_init(SegQueue::new)
}

#[inline]
fn default_ttl_dur() -> Duration {
    Duration::from_millis(DEFAULT_TTL_MS.load(Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// Read path (lock-free)
// ---------------------------------------------------------------------------

/// True if `host` (or a parent domain) is currently in the overlay under `cat`
/// and not expired. Walks the domain hierarchy like the FST path
/// (`a.b.example.com` -> `b.example.com` -> `example.com`).
#[inline]
pub fn dynamic_has_category(host: &str, cat: u64) -> bool {
    // Untouched until the first report — a free `Option` check on the hot path.
    let cell = match SNAPSHOT.get() {
        Some(c) => c,
        None => return false,
    };
    let snap = cell.load();
    if snap.map.is_empty() {
        return false;
    }
    let now = Instant::now();
    let mut h = host;
    loop {
        if let Some(e) = snap.map.get(h) {
            if e.cats & cat != 0 && e.expires > now {
                return true;
            }
        }
        match h.find('.') {
            Some(dot) => {
                h = &h[dot + 1..];
                if !h.contains('.') {
                    break;
                }
            }
            None => break,
        }
    }
    false
}

/// True if `host` (or a parent domain) is in the overlay under any category and
/// not expired.
#[inline]
pub fn dynamic_contains(host: &str) -> bool {
    let cell = match SNAPSHOT.get() {
        Some(c) => c,
        None => return false,
    };
    let snap = cell.load();
    if snap.map.is_empty() {
        return false;
    }
    let now = Instant::now();
    let mut h = host;
    loop {
        if let Some(e) = snap.map.get(h) {
            if e.expires > now {
                return true;
            }
        }
        match h.find('.') {
            Some(dot) => {
                h = &h[dot + 1..];
                if !h.contains('.') {
                    break;
                }
            }
            None => break,
        }
    }
    false
}

/// Current number of (possibly-expired-but-not-yet-reclaimed) overlay entries.
pub fn dynamic_len() -> usize {
    SNAPSHOT.get().map(|c| c.load().map.len()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Intake (non-blocking)
// ---------------------------------------------------------------------------

/// Record `host` as dynamically-bad under [`CAT_BAD`] with the default TTL.
/// Non-blocking and safe to call at high frequency from many threads.
#[inline]
pub fn report_bad(host: &str) {
    report_bad_with_ttl(host, CAT_BAD, BadReason::Other, default_ttl_dur());
}

/// Categorized report. `cats == 0` is normalized to [`CAT_BAD`].
#[inline]
pub fn report_bad_categorized(host: &str, cats: u64, reason: BadReason) {
    report_bad_with_ttl(host, cats, reason, default_ttl_dur());
}

/// Report with an explicit TTL (e.g. shorter for a transient wall).
pub fn report_bad_with_ttl(host: &str, cats: u64, reason: BadReason, ttl: Duration) {
    let cats = if cats == 0 { CAT_BAD } else { cats };
    let raw = get_host_from_url(host).unwrap_or(host).trim();
    if raw.is_empty() {
        return;
    }
    let host_norm = raw.to_ascii_lowercase();
    let at = Instant::now();
    let expires = at.checked_add(ttl).unwrap_or(at);

    // Sink first (borrowed) so the host app sees every report, then enqueue.
    invoke_sink(&BadReport {
        host: &host_norm,
        cats,
        reason,
        at,
        ttl,
    });

    queue().push(PendingReport {
        host: host_norm.into_boxed_str(),
        cats,
        expires,
    });
    let pending = PENDING.fetch_add(1, Ordering::Relaxed) + 1;
    maybe_merge(pending, at);
}

/// Bulk-load a persisted / fleet-broadcast list into the overlay on boot.
/// Each item is `(host, cats, ttl)`. One merge for the whole batch. Does **not**
/// invoke the sink (so a boot re-seed can't trigger a broadcast storm).
pub fn seed_dynamic<I>(entries: I)
where
    I: IntoIterator<Item = (String, u64, Duration)>,
{
    let now = Instant::now();
    let q = queue();
    let mut any = false;
    for (host, cats, ttl) in entries {
        let cats = if cats == 0 { CAT_BAD } else { cats };
        let raw = get_host_from_url(&host).unwrap_or(&host).trim();
        if raw.is_empty() {
            continue;
        }
        q.push(PendingReport {
            host: raw.to_ascii_lowercase().into_boxed_str(),
            cats,
            expires: now.checked_add(ttl).unwrap_or(now),
        });
        PENDING.fetch_add(1, Ordering::Relaxed);
        any = true;
    }
    if any {
        try_merge(now);
    }
}

/// Convenience: seed bare hosts as [`CAT_BAD`] with the default TTL.
pub fn seed_dynamic_hosts<I>(hosts: I)
where
    I: IntoIterator<Item = String>,
{
    let ttl = default_ttl_dur();
    seed_dynamic(hosts.into_iter().map(move |h| (h, CAT_BAD, ttl)));
}

// ---------------------------------------------------------------------------
// Merge (single-flight snapshot rebuild)
// ---------------------------------------------------------------------------

#[inline]
fn maybe_merge(pending: usize, now: Instant) {
    let batch = MERGE_BATCH.load(Ordering::Relaxed).max(1);
    if pending >= batch {
        try_merge(now);
        return;
    }
    let stale = match SNAPSHOT.get() {
        Some(c) => {
            let interval = Duration::from_millis(MERGE_INTERVAL_MS.load(Ordering::Relaxed));
            now.duration_since(c.load().built) >= interval
        }
        // No snapshot yet: fold the first report(s) in immediately.
        None => true,
    };
    if stale {
        try_merge(now);
    }
}

/// RAII release of the single-flight merge slot. Guarantees the flag is cleared
/// on every exit path — including an unexpected panic — so a merge can never
/// permanently wedge the overlay (no deadlock).
struct MergeGuard;
impl Drop for MergeGuard {
    fn drop(&mut self) {
        MERGE_IN_PROGRESS.store(false, Ordering::Release);
    }
}

fn try_merge(now: Instant) {
    if MERGE_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Another thread is merging; our entries stay queued for its drain
        // (or the next merge).
        return;
    }
    // From here on, the slot is released on any return/panic.
    let _slot = MergeGuard;

    let cell = snapshot_cell();
    let cur = cell.load_full();

    // Clone-on-write: carry forward only the still-live entries.
    let mut next: DynMap = new_map(cur.map.len());
    for (k, v) in cur.map.iter() {
        if v.expires > now {
            next.insert(k.clone(), *v);
        }
    }

    // Drain the intake, unioning categories and taking the latest expiry.
    let q = queue();
    while let Some(p) = q.pop() {
        PENDING.fetch_sub(1, Ordering::Relaxed);
        if p.expires <= now {
            continue;
        }
        match next.get_mut(&p.host) {
            Some(e) => {
                e.cats |= p.cats;
                if p.expires > e.expires {
                    e.expires = p.expires;
                }
            }
            None => {
                next.insert(
                    p.host,
                    DynEntry {
                        cats: p.cats,
                        expires: p.expires,
                    },
                );
            }
        }
    }

    let cap = MAX_ENTRIES.load(Ordering::Relaxed);
    if next.len() > cap {
        evict_to_cap(&mut next, cap);
    }

    cell.store(Arc::new(DynSnapshot {
        map: next,
        built: now,
    }));
    // `_slot` drops here, releasing MERGE_IN_PROGRESS.
}

/// Drop the soonest-to-expire entries until at most `cap` remain. Only runs when
/// the overlay exceeds the (large) safety cap, so the `O(n log n)` sort is rare.
fn evict_to_cap(map: &mut DynMap, cap: usize) {
    let over = map.len().saturating_sub(cap);
    if over == 0 {
        return;
    }
    let mut by_exp: Vec<(Instant, Box<str>)> =
        map.iter().map(|(k, e)| (e.expires, k.clone())).collect();
    by_exp.sort_unstable_by_key(|(exp, _)| *exp);
    for (_, k) in by_exp.into_iter().take(over) {
        map.remove(&k);
    }
}

/// Force any queued reports into the overlay now (best-effort, bounded). Use for
/// synchronous visibility after a boot [`seed_dynamic`] or in tests. **Never
/// blocks:** if another thread currently holds the single merge slot, this
/// yields and retries a bounded number of times, then returns — no spin-lock,
/// no deadlock.
pub fn flush() {
    for _ in 0..256 {
        try_merge(Instant::now());
        if PENDING.load(Ordering::Relaxed) == 0 && queue().is_empty() {
            return;
        }
        std::thread::yield_now();
    }
}

// ---------------------------------------------------------------------------
// Sink (fleet-share + durable capture)
// ---------------------------------------------------------------------------

/// Install the report sink. Called **synchronously on the reporting thread** for
/// every report — it MUST NOT block: push to your own channel and return. Used
/// to broadcast discoveries across the fleet and durably persist them for later
/// promotion into the static maps. Set-once (first call wins).
pub fn set_report_sink<F>(sink: F)
where
    F: Fn(&BadReport) + Send + Sync + 'static,
{
    let _ = REPORT_SINK.set(Box::new(sink));
}

#[inline]
fn invoke_sink(report: &BadReport) {
    if let Some(sink) = REPORT_SINK.get() {
        // The sink is host code; a panic there must not unwind the hot path.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink(report)));
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Default TTL applied to new reports (default 24h).
pub fn set_default_ttl(ttl: Duration) {
    DEFAULT_TTL_MS.store(ttl.as_millis().min(u64::MAX as u128) as u64, Ordering::Relaxed);
}

/// The current default TTL.
pub fn default_ttl() -> Duration {
    default_ttl_dur()
}

/// Queued reports before a merge fires (default 64). `1` = merge every report
/// (instant visibility). Clamped to at least 1.
pub fn set_merge_batch(n: usize) {
    MERGE_BATCH.store(n.max(1), Ordering::Relaxed);
}

/// Max time between merges while reports flow (default 5s).
pub fn set_merge_interval(d: Duration) {
    MERGE_INTERVAL_MS.store(d.as_millis().min(u64::MAX as u128) as u64, Ordering::Relaxed);
}

/// Hard cap on overlay size; soonest-to-expire entries are evicted past it
/// (default 100_000).
pub fn set_max_entries(n: usize) {
    MAX_ENTRIES.store(n.max(1), Ordering::Relaxed);
}

/// Opt-in daemon `std::thread` that periodically prunes expired entries (and
/// folds any queued reports). Reclaims memory in deployments that report
/// rarely. Idempotent — only the first call spawns a thread. No async runtime.
pub fn enable_background_pruner(interval: Duration) {
    if PRUNER_STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("spider-firewall-pruner".into())
        .spawn(move || loop {
            std::thread::sleep(interval);
            try_merge(Instant::now());
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    // One sequential test: the overlay is process-global, so running every
    // assertion on a single thread (no parallel reporters) keeps the
    // single-flight merge from being starved — deterministic with NO mutex.
    #[test]
    fn dynamic_overlay_behavior() {
        let hour = Duration::from_secs(3600);

        // report -> visible after flush; is_url_bad picks it up.
        assert!(!dynamic_contains("rt-evil.test"));
        report_bad("rt-evil.test");
        flush();
        assert!(dynamic_contains("rt-evil.test"));
        assert!(crate::is_url_bad("rt-evil.test"));

        // subdomain inherits a reported parent.
        report_bad("sub-evil.test");
        flush();
        assert!(dynamic_contains("a.b.sub-evil.test"));
        assert!(crate::is_url_bad("deep.a.b.sub-evil.test"));

        // TTL: expired entries read as absent even before a merge reclaims them.
        report_bad_with_ttl("ttl-evil.test", CAT_BAD, BadReason::Manual, Duration::from_millis(40));
        flush();
        assert!(dynamic_contains("ttl-evil.test"));
        std::thread::sleep(Duration::from_millis(60));
        assert!(!dynamic_contains("ttl-evil.test"));

        // category isolation; is_url_bad matches any category.
        report_bad_categorized("ads-only.test", crate::CAT_ADS, BadReason::Other);
        flush();
        assert!(dynamic_has_category("ads-only.test", crate::CAT_ADS));
        assert!(!dynamic_has_category("ads-only.test", CAT_BAD));
        assert!(crate::is_url_bad("ads-only.test"));

        // URL form is normalized to a bare lowercase host.
        report_bad("https://URL-Evil.test/path?x=1");
        flush();
        assert!(dynamic_contains("url-evil.test"));

        // bulk seed (no sink invocation).
        seed_dynamic(vec![
            ("seed-a.test".to_string(), CAT_BAD, hour),
            ("seed-b.test".to_string(), CAT_BAD, hour),
        ]);
        flush();
        assert!(dynamic_contains("seed-a.test"));
        assert!(dynamic_contains("seed-b.test"));

        // sink fires on report.
        static HITS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        set_report_sink(|r: &BadReport| {
            assert!(!r.host.is_empty());
            HITS.fetch_add(1, Ordering::Relaxed);
        });
        report_bad("sink-evil.test");
        flush();
        assert!(HITS.load(Ordering::Relaxed) >= 1);

        // empty / whitespace hosts are ignored (no panic, no empty key).
        report_bad("");
        report_bad("   ");
        flush();
        assert!(!dynamic_contains(""));
    }
}
