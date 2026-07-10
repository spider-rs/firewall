// build.rs
use hashbrown::HashSet;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct GithubContent {
    name: String,
    path: String,
    #[serde(rename = "type")]
    content_type: String,
}

/// Optional GitHub token for authenticated GitHub API calls. Authenticated
/// requests get 5,000 req/hr vs. 60/hr unauthenticated — the unauthenticated
/// budget is what makes a clean build of the `dynamic` feature flaky: the
/// directory-listing calls below burn through 60/hr and GitHub then returns a
/// JSON error *object* where an array is expected, panicking the build. Checked
/// in priority order; unset/empty ⇒ unauthenticated. Set `GITHUB_TOKEN` in CI /
/// the Docker build to make dynamic builds reliable.
fn github_token() -> Option<String> {
    ["GITHUB_TOKEN", "GH_TOKEN", "SPIDER_FIREWALL_GITHUB_TOKEN"]
        .iter()
        .copied()
        .find_map(|k| {
            env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
}

// ============================================================
//  Resilient fetch layer: timeout + retry/backoff + on-disk cache
//
//  Env knobs (each emits `cargo:rerun-if-env-changed` in main()):
//    SPIDER_FIREWALL_FETCH_TIMEOUT_SECS — per-request connect+total timeout (default 30)
//    SPIDER_FIREWALL_FETCH_RETRIES     — attempts per URL (default 4)
//    SPIDER_FIREWALL_CACHE_DIR         — cache dir override (default
//                                        $CARGO_HOME/spider_firewall-buildcache,
//                                        falling back to $HOME/.cache/spider_firewall)
//    SPIDER_FIREWALL_OFFLINE           — 1 ⇒ no network, serve from cache only
//
//  Every successful fetch is written through to the cache (atomic temp+rename,
//  keyed by an FNV-1a hash of the URL). When all retries fail, the cached copy
//  is served with a warning — so once a box has built successfully, a later
//  total upstream outage can no longer break the build. Only a genuinely
//  unrecoverable cold-cache+offline fetch of a FATAL source still panics.
// ============================================================

/// Read an env var, treating unset/whitespace-only as absent.
fn env_nonempty(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// `SPIDER_FIREWALL_OFFLINE=1` ⇒ skip the network entirely, cache only.
fn offline() -> bool {
    env_nonempty("SPIDER_FIREWALL_OFFLINE")
        .map_or(false, |v| v != "0" && !v.eq_ignore_ascii_case("false"))
}

fn env_u64(key: &str, default: u64) -> u64 {
    env_nonempty(key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Attempts per URL (`SPIDER_FIREWALL_FETCH_RETRIES`, default 4, clamped 1..=16).
fn fetch_retries() -> u32 {
    env_u64("SPIDER_FIREWALL_FETCH_RETRIES", 4).clamp(1, 16) as u32
}

/// Per-request connect + total timeout
/// (`SPIDER_FIREWALL_FETCH_TIMEOUT_SECS`, default 30s, clamped 1..=600).
fn fetch_timeout() -> Duration {
    Duration::from_secs(env_u64("SPIDER_FIREWALL_FETCH_TIMEOUT_SECS", 30).clamp(1, 600))
}

/// Stable FNV-1a 64-bit hash, hex-encoded — cache filename for a URL.
/// (Inline so we don't add a hashing crate; stable across Rust versions,
/// unlike `DefaultHasher`.)
fn fnv1a_hex(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Cache directory, resolved once: `SPIDER_FIREWALL_CACHE_DIR`, else a stable
/// persistent location that survives `cargo clean` ($CARGO_HOME, falling back
/// to ~/.cache). Returns `None` (⇒ retry-only, no cache) when no directory can
/// be resolved or created, rather than failing the build.
fn cache_dir() -> Option<&'static PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = if let Some(d) = env_nonempty("SPIDER_FIREWALL_CACHE_DIR") {
            PathBuf::from(d)
        } else if let Some(cargo_home) = env_nonempty("CARGO_HOME") {
            PathBuf::from(cargo_home).join("spider_firewall-buildcache")
        } else if let Some(home) = env_nonempty("HOME") {
            let cargo_default = PathBuf::from(&home).join(".cargo");
            if cargo_default.is_dir() {
                cargo_default.join("spider_firewall-buildcache")
            } else {
                PathBuf::from(home).join(".cache").join("spider_firewall")
            }
        } else {
            println!(
                "cargo:warning=spider_firewall: no cache dir resolvable (SPIDER_FIREWALL_CACHE_DIR/CARGO_HOME/HOME unset) — building without fetch cache"
            );
            return None;
        };
        match fs::create_dir_all(&dir) {
            Ok(()) => Some(dir),
            Err(e) => {
                println!(
                    "cargo:warning=spider_firewall: could not create fetch cache dir {}: {e} — building without fetch cache",
                    dir.display()
                );
                None
            }
        }
    })
    .as_ref()
}

fn cache_path(url: &str) -> Option<PathBuf> {
    cache_dir().map(|d| d.join(format!("{}.cache", fnv1a_hex(url))))
}

/// Read a cached body for `url`, returning it with the path it came from.
fn cache_read(url: &str) -> Option<(String, PathBuf)> {
    let path = cache_path(url)?;
    fs::read_to_string(&path).ok().map(|body| (body, path))
}

/// Write-through: persist a successfully fetched body atomically
/// (temp file + rename). Failures degrade to a warning, never an error.
fn cache_write(url: &str, body: &str) {
    let path = match cache_path(url) {
        Some(p) => p,
        None => return,
    };
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    if let Err(e) = fs::write(&tmp, body).and_then(|_| fs::rename(&tmp, &path)) {
        let _ = fs::remove_file(&tmp);
        println!(
            "cargo:warning=spider_firewall: failed to write fetch cache {}: {e}",
            path.display()
        );
    }
}

struct FetchError {
    status: Option<u16>,
    msg: String,
}

/// Transient statuses worth retrying; anything else 4xx-ish fails fast.
fn is_retryable_status(code: u16) -> bool {
    matches!(code, 408 | 429 | 500 | 502 | 503 | 504)
}

/// Exponential backoff (~500ms, 1s, 2s, 4s cap) + 0-250ms jitter derived from
/// the clock (no `rand` dep). A server `Retry-After` (capped at 30s) wins when
/// it asks for a longer wait.
fn backoff_delay(attempt: u32, retry_after: Option<Duration>) -> Duration {
    let base = Duration::from_millis(500u64 << attempt.saturating_sub(1).min(3));
    let jitter_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) % 250)
        .unwrap_or(0);
    let delay = base + Duration::from_millis(jitter_ms);
    match retry_after {
        Some(ra) => delay.max(ra.min(Duration::from_secs(30))),
        None => delay,
    }
}

/// GET `url` with up to `fetch_retries()` attempts. Retries transport errors
/// and retryable HTTP statuses (honoring `Retry-After` on 429/503); fails fast
/// on other non-success statuses. Returns the response body on 2xx.
fn http_get_with_retry(client: &Client, url: &str, github_api: bool) -> Result<String, FetchError> {
    let attempts = fetch_retries();
    let mut last_err = FetchError {
        status: None,
        msg: "no fetch attempted".to_string(),
    };
    for attempt in 1..=attempts {
        let mut req = client
            .get(url)
            .header("User-Agent", ua_generator::ua::spoof_ua());
        if github_api {
            req = req
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28");
            if let Some(token) = github_token() {
                req = req.header("Authorization", format!("Bearer {token}"));
            }
        }
        let mut retry_after: Option<Duration> = None;
        match req.send() {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    match response.text() {
                        Ok(body) => return Ok(body),
                        Err(e) => {
                            last_err = FetchError {
                                status: Some(status.as_u16()),
                                msg: format!("failed to read body: {e}"),
                            };
                        }
                    }
                } else if is_retryable_status(status.as_u16()) {
                    retry_after = response
                        .headers()
                        .get("Retry-After")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        .map(Duration::from_secs);
                    last_err = FetchError {
                        status: Some(status.as_u16()),
                        msg: format!("HTTP {status}"),
                    };
                } else {
                    // Non-retryable HTTP error (404, 403, ...): retrying won't help.
                    return Err(FetchError {
                        status: Some(status.as_u16()),
                        msg: format!("HTTP {status}"),
                    });
                }
            }
            Err(e) => {
                last_err = FetchError {
                    status: None,
                    msg: format!("transport error: {e}"),
                };
            }
        }
        if attempt < attempts {
            let delay = backoff_delay(attempt, retry_after);
            println!(
                "cargo:warning=spider_firewall: fetch attempt {attempt}/{attempts} for {url} failed ({}); retrying in {}ms",
                last_err.msg,
                delay.as_millis()
            );
            std::thread::sleep(delay);
        }
    }
    Err(last_err)
}

/// Fetch `url` with retries and write-through caching; fall back to the cached
/// copy when the network fails (or when offline). `Err` ONLY when the fetch is
/// unrecoverable AND no cache entry exists — the caller decides whether that is
/// fatal (`fetch_text`) or degrades to empty (`fetch_text_opt`).
fn fetch_text_resilient(client: &Client, url: &str) -> Result<String, String> {
    if offline() {
        return match cache_read(url) {
            Some((body, path)) => {
                println!(
                    "cargo:warning=spider_firewall: offline mode — using cached copy of {url} ({})",
                    path.display()
                );
                Ok(body)
            }
            None => Err(format!(
                "SPIDER_FIREWALL_OFFLINE is set and no cached copy of {url} exists"
            )),
        };
    }
    match http_get_with_retry(client, url, false) {
        Ok(body) => {
            cache_write(url, &body);
            Ok(body)
        }
        Err(e) => match cache_read(url) {
            Some((body, path)) => {
                println!(
                    "cargo:warning=spider_firewall: using stale cached copy of {url} ({}) after fetch failure",
                    path.display()
                );
                Ok(body)
            }
            None => Err(format!(
                "{} (after {} attempt(s); no cached copy available)",
                e.msg,
                fetch_retries()
            )),
        },
    }
}

/// Fetch a GitHub `contents` API listing as `Vec<GithubContent>`, authenticated
/// when a token is configured, with retry/backoff and a cached-listing fallback.
/// DEGRADES GRACEFULLY: any unrecoverable failure — transport error, rate
/// limit, or a non-array error body — emits a `cargo:warning` and returns an
/// empty listing so that one source is simply skipped, instead of the
/// `.expect()` panic that used to fail the entire build (every other blocklist
/// source still loads). With a token set, the happy path is unchanged.
fn fetch_github_contents(client: &Client, url: &str) -> Vec<GithubContent> {
    let parse = |body: &str| serde_json::from_str::<Vec<GithubContent>>(body);
    if offline() {
        if let Some((body, path)) = cache_read(url) {
            if let Ok(contents) = parse(&body) {
                println!(
                    "cargo:warning=spider_firewall: offline mode — using cached copy of {url} ({})",
                    path.display()
                );
                return contents;
            }
        }
        println!(
            "cargo:warning=spider_firewall: offline mode and no cached GitHub listing for {url} — skipping this source"
        );
        return Vec::new();
    }
    match http_get_with_retry(client, url, true) {
        Ok(body) => match parse(&body) {
            Ok(contents) => {
                // Only cache a body that parsed as a real listing (never a
                // rate-limit error object).
                cache_write(url, &body);
                contents
            }
            Err(e) => {
                println!(
                    "cargo:warning=spider_firewall: could not parse GitHub listing {url}: {e} — skipping this source"
                );
                Vec::new()
            }
        },
        Err(err) => {
            if let Some((body, path)) = cache_read(url) {
                if let Ok(contents) = parse(&body) {
                    println!(
                        "cargo:warning=spider_firewall: using stale cached copy of {url} ({}) after fetch failure",
                        path.display()
                    );
                    return contents;
                }
            }
            let hint = if matches!(err.status, Some(401) | Some(403) | Some(429)) {
                " — GitHub API auth/rate-limit; set GITHUB_TOKEN to raise the limit to 5,000/hr"
            } else {
                ""
            };
            println!(
                "cargo:warning=spider_firewall: GitHub listing fetch failed for {url} ({}){hint} — skipping this source",
                err.msg
            );
            Vec::new()
        }
    }
}

/// Category bitmask flags — must stay in sync with lib.rs.
const CAT_BAD: u64 = 1;
const CAT_ADS: u64 = 2;
const CAT_TRACKING: u64 = 4;
const CAT_GAMBLING: u64 = 8;

// local domains to include past ignore. These are valid domains.
static WHITE_LIST_AD_DOMAINS: &[&str] = &[
    "anydesk.com",
    "firstaidbeauty.com",
    "teads.com",
    "appchair.com",
    "ninjacat.io",
    "oceango.net",
    "center.io",
    "bing.com",
    "unity3d.com",
    "adguard.com",
    "bitdefender.com",
    "blogspot.com",
    "bytedance.com",
    "comcast.net",
    "duckdns.org",
    "dyndns.org",
    "fontawesome.com",
    "grammarly.com",
    "onenote.com",
    "opendns.com",
    "surfshark.com",
    "teamviewer.com",
    "tencent.com",
    "tiktok.com",
    "yandex.net",
    "zoho.com",
    "tiktokcdn-us.com",
    "tiktokcdn.com",
    "tiktokv.com",
    "tiktokrow-cdn.com",
    "tiktokv.us",
    "wpengine.com",
    "ning.com",
    "rakuten.com",
    "naver.com",
    "panopto.com",
    "techsmith.com",
    "screencastify.com",
    "magix.com",
    "winzip.com",
    "webroot.com",
    "webrootcloudav.com",
    "webrootdns.net",
    "webrootmobile.com",
    "webrootmultiplatform.com",
    "webrootanywhere.com",
    "amazonpay.com",
    "douyin.com",
    "lemon8-app.com",
    "lemon8-app.us",
    "lemon8cdn.com",
    "strikingly.com",
    "mystrikingly.com",
    "framer.app",
    "framer.ai",
    "framer.website",
    "rt.com",
    "clickz.com",
    "ask.com",
    "sogou.com",
    "movavi.com",
    "bitbucket.io",
    "codesandbox.io",
    "godaddysites.com",
    "ngrok.io",
    "pythonanywhere.com",
    "repl.co",
    "stackblitz.io",
    "charter.net",
    "xe.com",
    "example3.com",
    "interactions.com",
    "nekansascitynews.com",
    "downriversundaytimes.com",
    "control.com",
    "newswithviews.com",
    "weeklyworldnews.com",
    "mmaglobal.com",
    "dickssportinggoods.com",
    "dickies.com",
    "dickblick.com",
    "dicksdrivein.com",
    "dickson-constant.com",
    "dicksonone.com",
    "dickclark.com",
    "salesforce.com",
    "webmd.com",
    "dynatrace.com",
    "newrelic.com",
    "sumologic.com",
    "embassysuites.com",
    "poe.com",
    "sierraspace.com",
    "trustpilot.com",
    // False positives swept into aggressive phishing/scam/malware feeds
    // (BlockListProject, malware-filter, etc.). All are well-known legitimate
    // businesses/institutions — not malware. Ad-tech/tracking/porn/gambling and
    // typosquat entries are intentionally NOT listed here (they remain blocked).
    // -- Security / software / remote-access vendors
    "checkpoint.com",
    "fortinet.com",
    "pandasecurity.com",
    "realvnc.com",
    "tightvnc.com",
    "splashtop.com",
    "screenconnect.com",
    "logmein.com",
    "gotomeeting.com",
    "goto.com",
    "join.me",
    "8x8.com",
    "insecure.org",
    "traccar.org",
    "ionicframework.com",
    "nicepage.io",
    // -- VPN providers
    "nordvpn.com",
    "expressvpn.com",
    "protonvpn.com",
    "cyberghostvpn.com",
    "purevpn.com",
    "hotspotshield.com",
    "windscribe.com",
    "mullvad.net",
    "privateinternetaccess.com",
    "tunnelbear.com",
    "openvpn.net",
    "wireguard.com",
    "hidemyass.com",
    // -- Microsoft / Google properties
    "skype.com",
    "windowsphone.com",
    "yammer.com",
    "dns.google",
    "plus.google.com",
    "maps.app.goo.gl",
    // -- SaaS (support / chat / survey / productivity / AI)
    "surveymonkey.com",
    "questionpro.com",
    "survio.com",
    "alchemer.com",
    "surveygizmo.com",
    "livechat.com",
    "livechatinc.com",
    "tawk.to",
    "tawk.help",
    "intercom.com",
    "intercom.help",
    "clickup.com",
    "rocket.chat",
    "crisp.chat",
    "smartsupp.com",
    "olark.com",
    "tidio.com",
    "drift.com",
    "helpscout.net",
    "kayako.com",
    "superoffice.com",
    "getpocket.com",
    "donorbox.org",
    "casetext.com",
    "character.ai",
    "jasper.ai",
    "writesonic.com",
    "frase.io",
    "clickfunnels.com",
    // -- Dev / hosting platforms (consistent with the sandbox hosts above)
    "onrender.com",
    "glitch.me",
    "wixstudio.com",
    // -- Networking / privacy
    "tailscale.com",
    "torproject.org",
    // -- Retail / consumer
    "rei.com",
    "landsend.com",
    "discovercars.com",
    "talent.com",
    "vectorstock.com",
    "hmv.co.jp",
    // -- Finance / telecom / industry
    "remitly.com",
    "xoom.com",
    "commbank.com.au",
    "nseindia.com",
    "airtel.in",
    "chinamobile.com",
    "sonymobile.com",
    "boehringer-ingelheim.com",
    "hikvision.com",
    // -- Education / government / nonprofit / reference
    "vam.ac.uk",
    "ipbes.net",
    "constitution.org",
    // -- Reputable news / media
    "wnycstudios.org",
    "zaobao.com.sg",
    "ekstrabladet.dk",
    "phnompenhpost.com",
    "atimes.com",
    "kinopoisk.ru"
];

type BuildResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// FATAL fetch with retry + cache fallback: panics ONLY when the network is
/// unrecoverable after all retries AND there is no cached copy — the genuinely
/// cold-cache+offline case (the same builds that used to fail on a single blip).
fn fetch_text(client: &Client, url: &str) -> String {
    fetch_text_resilient(client, url)
        .unwrap_or_else(|e| panic!("Failed to fetch {}: {}", url, e))
}

/// Parse a hosts-format file (e.g. `0.0.0.0 domain` or `127.0.0.1 domain`),
/// skipping comments, localhost aliases, and ip6-* entries.
fn parse_hosts_lines(body: &str, out: &mut HashSet<String>) {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let _ip = match parts.next() {
            Some(v) => v,
            None => continue,
        };
        let domain = match parts.next() {
            Some(v) => v,
            None => continue,
        };
        if matches!(
            domain,
            "localhost" | "0.0.0.0" | "local" | "localhost.localdomain" | "broadcasthost"
        ) || domain.contains("ip6-")
        {
            continue;
        }
        out.insert(domain.to_string());
    }
}

/// Parse a plain-text domain list (one domain per line), skipping comments and
/// empty lines. Handles optional inline comments (e.g. `domain # note`).
fn parse_domain_lines(body: &str, out: &mut HashSet<String>) {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let domain = trimmed.split_whitespace().next().unwrap_or("");
        if !domain.is_empty() {
            out.insert(domain.to_string());
        }
    }
}

/// Like `fetch_text` but NON-FATAL: returns an empty string on failure instead of
/// panicking, emitting a `cargo:warning`. Used for feeds that are rate-limited or
/// revocable (e.g. Spamhaus DROP, ~1 download/day) so a transient fetch failure
/// cannot break the build — the source simply contributes no entries. Shares the
/// same retry + cache-fallback path as `fetch_text`.
fn fetch_text_opt(client: &Client, url: &str) -> String {
    match fetch_text_resilient(client, url) {
        Ok(body) => body,
        Err(e) => {
            println!(
                "cargo:warning=spider_firewall: failed to fetch {} ({}); continuing with no entries from this source",
                url, e
            );
            String::new()
        }
    }
}

/// Convert an IPv4 CIDR (or a bare IPv4, treated as `/32`) to an inclusive
/// `(start, end)` u32 range. Returns `None` for anything not a valid IPv4 CIDR.
fn cidr_v4_to_range(s: &str) -> Option<(u32, u32)> {
    let (addr_str, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok()?),
        None => (s, 32u8),
    };
    if prefix > 32 {
        return None;
    }
    let addr: std::net::Ipv4Addr = addr_str.parse().ok()?;
    let base = u32::from(addr);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let start = base & mask;
    let end = start | !mask;
    Some((start, end))
}

/// Parse a Spamhaus DROP-style list of IPv4 CIDR ranges (e.g. `1.2.3.0/24 ; SBL123`).
/// Lines beginning with `;` or `#` are comments; inline `;`/whitespace comments are
/// stripped. Appends inclusive `(start, end)` u32 ranges, skipping invalid entries.
fn parse_cidr_v4_lines(body: &str, out: &mut Vec<(u32, u32)>) {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        let token = trimmed.split([';', ' ', '\t']).next().unwrap_or("").trim();
        if token.is_empty() {
            continue;
        }
        if let Some(range) = cidr_v4_to_range(token) {
            out.push(range);
        }
    }
}

/// Sort and merge overlapping/adjacent `(start, end)` ranges into a minimal,
/// sorted, non-overlapping set (suitable for binary-search lookup at runtime).
fn merge_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            // Merge when overlapping or directly adjacent (guarding u32 overflow).
            if s <= last.1 || (last.1 != u32::MAX && s <= last.1 + 1) {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        merged.push((s, e));
    }
    merged
}

fn main() -> BuildResult<()> {
    println!("cargo:rerun-if-env-changed=SPIDER_FIREWALL_OFFLINE");
    println!("cargo:rerun-if-env-changed=SPIDER_FIREWALL_CACHE_DIR");
    println!("cargo:rerun-if-env-changed=SPIDER_FIREWALL_FETCH_RETRIES");
    println!("cargo:rerun-if-env-changed=SPIDER_FIREWALL_FETCH_TIMEOUT_SECS");

    // Per-request connect + total timeout so a hung upstream connection can
    // never block the build indefinitely.
    let timeout = fetch_timeout();
    let client = Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
        .expect("spider_firewall: failed to build HTTP client");

    // Category flags
    let include_bad = env::var("CARGO_FEATURE_BAD").is_ok();
    let include_ads = env::var("CARGO_FEATURE_ADS").is_ok();
    let include_tracking = env::var("CARGO_FEATURE_TRACKING").is_ok();
    let include_gambling = env::var("CARGO_FEATURE_GAMBLING").is_ok();

    // Tier flags (large implies medium implies small via Cargo feature deps)
    let tier_small = env::var("CARGO_FEATURE_SMALL").is_ok();
    let tier_medium = env::var("CARGO_FEATURE_MEDIUM").is_ok();
    let tier_large = env::var("CARGO_FEATURE_LARGE").is_ok();

    let mut unique_entries = HashSet::<String>::new();
    let mut unique_ads_entries = HashSet::<String>::new();
    let mut unique_tracking_entries = HashSet::<String>::new();
    let mut unique_gambling_entries = HashSet::<String>::new();

    let need_shadow =
        tier_small && (include_bad || include_ads || include_tracking || include_gambling);
    let need_1hosts = tier_small && (include_ads || include_tracking);
    let need_spider = tier_small && include_bad;

    // ============================================================
    //  SMALL tier sources
    // ============================================================

    // ----------------------------
    // ShadowWhisperer/BlockLists
    // ----------------------------
    if need_shadow {
        let base_url = "https://api.github.com/repos/ShadowWhisperer/BlockLists/contents/RAW";
        let contents = fetch_github_contents(&client, base_url);

        let skip_list = vec![
            "Cryptocurrency",
            "Dating",
            "Fonts",
            "Microsoft",
            "Marketing",
            "Wild_Tracking",
            "Free",
        ];

        for item in contents {
            if skip_list.contains(&item.name.as_str()) {
                continue;
            }

            if item.content_type != "file" {
                continue;
            }

            let is_tracking = item.name == "Wild_Tracking" || item.name == "Tracking";
            let is_ads = item.name == "Wild_Ads" || item.name == "Ads";
            let is_gambling = item.name == "Gambling";
            let is_bad = !is_tracking && !is_ads && !is_gambling;

            // Skip downloads for disabled categories.
            if (is_tracking && !include_tracking)
                || (is_ads && !include_ads)
                || (is_gambling && !include_gambling)
                || (is_bad && !include_bad)
            {
                continue;
            }

            let file_url = format!(
                "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/{}",
                item.path
            );
            let file_content = fetch_text(&client, &file_url);

            if is_tracking {
                for line in file_content.lines() {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_tracking_entries.insert(s.to_string());
                    }
                }
            } else if is_ads {
                for line in file_content.lines() {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_ads_entries.insert(s.to_string());
                    }
                }
            } else if is_gambling {
                for line in file_content.lines() {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_gambling_entries.insert(s.to_string());
                    }
                }
            } else {
                for line in file_content.lines() {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_entries.insert(s.to_string());
                    }
                }
            }
        }
    }

    // ----------------------------
    // badmojr/1Hosts (Lite)
    // ----------------------------
    if need_1hosts {
        let base_url = "https://api.github.com/repos/badmojr/1Hosts/contents/Lite/";
        let contents = fetch_github_contents(&client, base_url);
        let skip_list = vec!["rpz", "domains.wildcards", "wildcards", "unbound.conf"];

        for item in contents {
            if skip_list.contains(&item.name.as_str()) {
                continue;
            }

            let want_domains = item.content_type == "file"
                && item.name == "domains.txt"
                && include_tracking;
            let want_adblock =
                item.content_type == "file" && item.name == "adblock.txt" && include_ads;

            if !want_domains && !want_adblock {
                continue;
            }

            let file_url = format!(
                "https://raw.githubusercontent.com/badmojr/1Hosts/master/{}",
                item.path
            );
            let file_content = fetch_text(&client, &file_url);

            if want_domains {
                for line in file_content.lines().skip(15) {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_tracking_entries.insert(s.to_string());
                    }
                }
            } else {
                for line in file_content.lines().skip(15) {
                    let s = line.trim();
                    if !s.is_empty() {
                        let mut ad_url = s.replacen("||", "", 1);
                        if ad_url.ends_with('^') {
                            ad_url.pop();
                        }
                        if !ad_url.is_empty() {
                            unique_ads_entries.insert(ad_url);
                        }
                    }
                }
            }
        }
    }

    // ----------------------------
    // spider-rs/bad_websites additional file
    // ----------------------------
    if need_spider {
        let additional_url =
            "https://raw.githubusercontent.com/spider-rs/bad_websites/main/websites.txt";
        let additional_content = fetch_text(&client, additional_url);

        for line in additional_content.lines() {
            let entry = line.trim_matches(|c| c == '"' || c == ',').trim();
            if !entry.is_empty() {
                unique_entries.insert(entry.to_string());
            }
        }
    }

    // ----------------------------
    // Steven Black Unified Hosts
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        );
        parse_hosts_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Malware
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/malware-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Phishing
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/phishing-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Scam
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/scam-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // URLhaus Filter — Malware Domains
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // StevenBlack hosts — Porn/Adult aggregate
    // Hosts-file format; dedups against the base StevenBlack hosts above.
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
        );
        parse_hosts_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // malware-filter — Phishing Domains (OpenPhish/IPThreat upstreams)
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt",
        );
        parse_hosts_lines(&body, &mut unique_entries);
    }

    // ============================================================
    //  MEDIUM tier sources (threat-intelligence hardening)
    // ============================================================

    // ----------------------------
    // Block List Project — Ransomware
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/ransomware-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Fraud
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/fraud-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Abuse
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/abuse-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Phishing.Database — Active Domains
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Stamparm/maltrail — Suspicious Domains
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/domain.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // phishdestroy/destroylist — Primary Active (DNS-verified, MIT)
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/domains.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // durablenapkin/scamblocklist — Curated scam & fraud domains (MIT)
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
        );
        parse_hosts_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // HaGeZi Threat Intelligence Feeds — Mini tier
    // Plain-domain format; same GPLv3 as the large-tier TIF; ~169k entries;
    // updated every 6h. Fills TIF coverage at medium before the full ~700k list
    // kicks in at large. Overlapping entries are deduplicated at merge time.
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // abuse.ch ThreatFox — Malware Domain IOCs (hosts-file format, CC0)
    // Active malware C2 and distribution domains from the ThreatFox community
    // IOC platform: covers Cobalt Strike, Emotet, QakBot, njRAT, and many more
    // families beyond what Feodo Tracker covers. IOCs expire after 6 months.
    // Generated every 5 min; fetched non-fatally so a transient failure or
    // rate-limit yields no entries rather than breaking the build.
    // (c) abuse.ch — https://threatfox.abuse.ch — CC0, any use including commercial.
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text_opt(
            &client,
            "https://threatfox.abuse.ch/downloads/hostfile/",
        );
        parse_hosts_lines(&body, &mut unique_entries);
    }

    // ============================================================
    //  LARGE tier sources (comprehensive protection)
    // ============================================================

    // ----------------------------
    // Block List Project — Redirect
    // ----------------------------
    if tier_large && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/redirect-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Tracking
    // ----------------------------
    if tier_large && include_tracking {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/tracking-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_tracking_entries);
    }

    // ----------------------------
    // Block List Project — Ads
    // ----------------------------
    if tier_large && include_ads {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/ads-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_ads_entries);
    }

    // ----------------------------
    // HaGeZi Threat Intelligence Feeds — Malware/Phishing/Scam Domains
    // (Replaces the retired stamparm/maltrail aggregated malware/domain.txt.)
    // ----------------------------
    if tier_large && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // abuse.ch URLhaus — Full Hostfile
    // ----------------------------
    if tier_large && include_bad {
        let body = fetch_text(&client, "https://urlhaus.abuse.ch/downloads/hostfile/");
        parse_hosts_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Apply whitelist to BAD only
    // ----------------------------
    let whitelist: HashSet<&'static str> = WHITE_LIST_AD_DOMAINS.iter().copied().collect();

    // Check if a domain or any of its parent domains are whitelisted.
    let is_whitelisted = |domain: &str| -> bool {
        if whitelist.contains(domain) {
            return true;
        }
        let mut h = domain;
        while let Some(dot) = h.find('.') {
            h = &h[dot + 1..];
            if !h.contains('.') {
                break;
            }
            if whitelist.contains(h) {
                return true;
            }
        }
        false
    };

    // ----------------------------
    // Merge into a single BTreeMap<String, u64> for the unified FST Map.
    // The value is a bitmask of categories.
    // BTreeMap gives us sorted iteration which fst::MapBuilder requires.
    // ----------------------------
    let mut unified = BTreeMap::<String, u64>::new();

    if include_bad {
        for domain in unique_entries
            .into_iter()
            .filter(|e| !is_whitelisted(e.as_str()))
        {
            *unified.entry(domain).or_insert(0) |= CAT_BAD;
        }
    }

    if include_ads {
        for domain in unique_ads_entries {
            *unified.entry(domain).or_insert(0) |= CAT_ADS;
        }
    }

    if include_tracking {
        for domain in unique_tracking_entries {
            *unified.entry(domain).or_insert(0) |= CAT_TRACKING;
        }
    }

    if include_gambling {
        for domain in unique_gambling_entries {
            *unified.entry(domain).or_insert(0) |= CAT_GAMBLING;
        }
    }

    // ----------------------------
    // Prune subdomains whose parent domain is already in the same categories.
    // e.g. "sub.example.com" with bitmask 1 is redundant if "example.com" has bitmask 1.
    // The lookup functions walk up parent domains, so these are still matched.
    // ----------------------------
    let keys_to_check: Vec<String> = unified.keys().cloned().collect();
    for key in &keys_to_check {
        let child_mask = match unified.get(key) {
            Some(&m) => m,
            None => continue,
        };
        // Walk up parent domains.
        let mut rest = key.as_str();
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            // Need at least one dot in the parent (i.e., "foo.tld" not just "tld").
            if !rest.contains('.') {
                break;
            }
            if let Some(&parent_mask) = unified.get(rest) {
                // Remove the child if the parent covers all its categories.
                if parent_mask & child_mask == child_mask {
                    unified.remove(key);
                    break;
                }
            }
        }
    }

    // ----------------------------
    // Write unified FST Map
    // ----------------------------
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let fst_path = out_dir.join("firewall.fst");

    let w = BufWriter::new(File::create(&fst_path)?);
    let mut builder = fst::MapBuilder::new(w)?;

    for (key, value) in &unified {
        if !key.is_empty() {
            builder.insert(key, *value)?;
        }
    }

    builder.finish()?;

    // ----------------------------
    // Generate Rust include file
    // ----------------------------
    let dest_rs = out_dir.join("bad_websites.rs");
    fs::write(
        &dest_rs,
        r#"
// Auto-generated by build.rs — unified FST map with category bitmasks.
pub static FIREWALL_FST_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/firewall.fst"));
"#,
    )?;

    // ----------------------------
    // IP blocking (feature = "ip") — known-bad IPv4 ranges.
    //
    // Source: The Spamhaus Project DROP list (https://www.spamhaus.org/drop/).
    // Free for any use including commercial under the DROP terms; attribution is
    // retained in the generated file + README. The feed is rate-limited
    // (~1 download/day) and revocable, so it is fetched NON-FATALLY: a failed or
    // rate-limited fetch yields zero ranges rather than breaking the build.
    // ----------------------------
    let include_ip = env::var("CARGO_FEATURE_IP").is_ok();
    let mut ip_ranges_v4: Vec<(u32, u32)> = Vec::new();
    if include_ip {
        let body = fetch_text_opt(&client, "https://www.spamhaus.org/drop/drop.txt");
        parse_cidr_v4_lines(&body, &mut ip_ranges_v4);
    }

    // ----------------------------
    // abuse.ch Feodo Tracker — Botnet C2 IPv4 (CC0)
    // Bare-IP list of confirmed C2 servers for Dridex, Emotet/Heodo, TrickBot,
    // QakBot, and BazarLoader — updated every 5 minutes. Non-fatal fetch: a
    // transient failure contributes no entries rather than breaking the build.
    // (c) abuse.ch — https://feodotracker.abuse.ch — CC0, any use including commercial.
    // ----------------------------
    if include_ip {
        let body = fetch_text_opt(
            &client,
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        );
        parse_cidr_v4_lines(&body, &mut ip_ranges_v4);
    }

    // ----------------------------
    // ThreatFox IOC IPv4 — Broader Malware C2/Distribution IPs (CC0)
    // Bare-IP list mirrored hourly from abuse.ch ThreatFox IOC platform.
    // Complements Feodo Tracker (botnet-specific) with a wider set of malware
    // families (Cobalt Strike C2, Metasploit, njRAT, AsyncRAT, etc.). Gated to
    // medium tier because the broader scope (vs. confirmed botnet-only Feodo)
    // carries slightly higher shared-hosting FP risk at very small build sizes.
    // Non-fatal fetch: a transient failure contributes no entries.
    // Data: (c) abuse.ch ThreatFox (CC0). Mirror: elliotwutingfeng (BSD-3-Clause).
    // https://github.com/elliotwutingfeng/ThreatFox-IOC-IPs
    // ----------------------------
    if include_ip && tier_medium {
        let body = fetch_text_opt(
            &client,
            "https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/main/ips.txt",
        );
        parse_cidr_v4_lines(&body, &mut ip_ranges_v4);
    }

    // ----------------------------
    // malware-filter / URLhaus filter — Malware-Hosting IPs (CC0 + MIT)
    // IPs from currently-online URLhaus malware-distribution URLs where the URL
    // host is a bare IP address rather than a domain name. Updated 2×/day.
    // Gated to large tier due to the broader false-positive surface of shared
    // hosting: a single IP may serve both malware paths and legitimate content.
    // (c) curben — https://gitlab.com/malware-filter/urlhaus-filter — CC0 + MIT.
    // ----------------------------
    if include_ip && tier_large {
        let body = fetch_text_opt(
            &client,
            "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-dnscrypt-blocked-ips.txt",
        );
        parse_cidr_v4_lines(&body, &mut ip_ranges_v4);
    }

    let ip_ranges_v4 = merge_ranges(ip_ranges_v4);

    // Rate-limit / revocation safety. All IP sources are fetched non-fatally; a
    // failed fetch yields zero entries rather than breaking the build. Surface
    // loudly when ALL sources return nothing, and in strict mode fail the build
    // so production never *silently* ships with IP blocking off.
    if include_ip {
        println!("cargo:rerun-if-env-changed=SPIDER_FIREWALL_IP_STRICT");
        if ip_ranges_v4.is_empty() {
            let msg = "spider_firewall: `ip` feature is enabled but all IP blocklist sources \
                       returned 0 ranges (rate-limited, blocked, or revoked) — IP blocking will be \
                       INACTIVE in this build";
            if env::var("SPIDER_FIREWALL_IP_STRICT").is_ok() {
                return Err(format!(
                    "{msg}. SPIDER_FIREWALL_IP_STRICT is set, so the build fails instead of \
                     silently disabling IP blocking — retry once the ~1/day limit resets, or unset \
                     the variable to allow the graceful empty fallback."
                )
                .into());
            }
            println!(
                "cargo:warning={msg}. Set SPIDER_FIREWALL_IP_STRICT=1 to fail the build instead."
            );
        } else {
            println!(
                "cargo:warning=spider_firewall: embedded {} IPv4 range(s) from all IP blocklists",
                ip_ranges_v4.len()
            );
        }
    }

    let mut ip_rs = String::from(
        "// Auto-generated by build.rs — known-bad IPv4 ranges (inclusive (start, end) u32),\n\
         // sorted and merged for binary-search lookup.\n\
         // Sources:\n\
         //   Spamhaus DROP (https://www.spamhaus.org/drop/) — Spamhaus DROP terms\n\
         //   (free for any use, attribution required). (c) The Spamhaus Project.\n\
         //\n\
         //   abuse.ch Feodo Tracker (https://feodotracker.abuse.ch/) — CC0.\n\
         //   (c) abuse.ch\n\
         //\n\
         //   ThreatFox IOC IPv4 addresses [medium tier]\n\
         //   (https://github.com/elliotwutingfeng/ThreatFox-IOC-IPs) — CC0 (data) + BSD-3-Clause (mirror).\n\
         //   Data (c) abuse.ch ThreatFox.\n\
         //\n\
         //   malware-filter URLhaus-filter malware-hosting IPs [large tier]\n\
         //   (https://gitlab.com/malware-filter/urlhaus-filter) — CC0 + MIT.\n\
         pub static BAD_IP_RANGES_V4: &[(u32, u32)] = &[\n",
    );
    for (s, e) in &ip_ranges_v4 {
        ip_rs.push_str(&format!("    ({}, {}),\n", s, e));
    }
    ip_rs.push_str("];\n");
    fs::write(out_dir.join("bad_ips.rs"), ip_rs)?;

    Ok(())
}
