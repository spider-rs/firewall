include!(concat!(env!("OUT_DIR"), "/bad_websites.rs"));

/// Firewall handling list.
pub mod firewall {
    use std::sync::OnceLock;

    /// General malice list.
    pub static GLOBAL_BAD_WEBSITES: OnceLock<&phf::Set<&'static str>> = OnceLock::new();
    /// Ads list.
    pub static GLOBAL_ADS_WEBSITES: OnceLock<&phf::Set<&'static str>> = OnceLock::new();
    /// Tracking or trackers list.
    pub static GLOBAL_TRACKING_WEBSITES: OnceLock<&phf::Set<&'static str>> = OnceLock::new();
    /// Gambling websites list.
    pub static GLOBAL_GAMBLING_WEBSITES: OnceLock<&phf::Set<&'static str>> = OnceLock::new();
    /// Networking XHR|Fetch general list.
    pub static GLOBAL_NETWORKING_WEBSITES: OnceLock<&phf::Set<&'static str>> = OnceLock::new();

    #[macro_export]
    /// Defines a set of websites under a specified category. Available categories
    /// include "ads", "tracking", "gambling", "networking", and a default category for any other strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use spider_firewall::define_firewall;
    /// use spider_firewall::{is_ad_website_url, is_gambling_website_url, is_bad_website_url, is_networking_url};
    ///
    /// define_firewall!("ads", "example-ad.com", "another-ad.com");
    /// assert!(is_ad_website_url("example-ad.com"));
    ///
    /// define_firewall!("gambling", "example-gambling.com");
    /// assert!(is_gambling_website_url("example-gambling.com"));
    ///
    /// define_firewall!("networking", "a.ping.com");
    /// assert!(is_networking_url("a.ping.com"));
    ///
    /// define_firewall!("unknown", "example-unknown.com");
    /// assert!(is_bad_website_url("example-unknown.com"));
    /// ```
    macro_rules! define_firewall {
        ($category:expr, $($site:expr),* $(,)?) => {
            match $category {
                "ads" => {
                    if $crate::firewall::GLOBAL_ADS_WEBSITES.get().is_none() {
                        $crate::firewall::GLOBAL_ADS_WEBSITES
                            .set(&phf::phf_set! { $($site),* })
                            .expect("Initialization already set.");
                    }
                },
                "tracking" => {
                    if $crate::firewall::GLOBAL_TRACKING_WEBSITES.get().is_none() {
                        $crate::firewall::GLOBAL_TRACKING_WEBSITES
                            .set(&phf::phf_set! { $($site),* })
                            .expect("Initialization already set.");
                    }
                },
                "gambling" => {
                    if $crate::firewall::GLOBAL_GAMBLING_WEBSITES.get().is_none() {
                        $crate::firewall::GLOBAL_GAMBLING_WEBSITES
                            .set(&phf::phf_set! { $($site),* })
                            .expect("Initialization already set.");
                    }
                },
                "networking" => {
                    if $crate::firewall::GLOBAL_NETWORKING_WEBSITES.get().is_none() {
                        $crate::firewall::GLOBAL_NETWORKING_WEBSITES
                            .set(&phf::phf_set! { $($site),* })
                            .expect("Initialization already set.");
                    }
                },
                _ => {
                    if $crate::firewall::GLOBAL_BAD_WEBSITES.get().is_none() {
                        $crate::firewall::GLOBAL_BAD_WEBSITES
                            .set(&phf::phf_set! { $($site),* })
                            .expect("Initialization already set.");
                    }
                },
            }
        };
    }
}

use std::sync::OnceLock;

/// Runtime "discovered-bad" overlay + feedback funnel. Opt-in via the `dynamic`
/// feature; when off, none of this compiles and the read path is byte-identical.
#[cfg(feature = "dynamic")]
pub mod dynamic;

/// Category bitmask flags — must stay in sync with build.rs.
///
/// Threat feeds only: malware, phishing, scam and fraud. This is the bit
/// [`is_bad_website_url`] reads, so it is the one to hard-refuse on.
pub const CAT_BAD: u64 = 1;
/// Ads category bit.
pub const CAT_ADS: u64 = 2;
/// Tracking category bit.
pub const CAT_TRACKING: u64 = 4;
/// Gambling category bit.
pub const CAT_GAMBLING: u64 = 8;
/// Adult content lists (StevenBlack porn, ShadowWhisperer Adult). Before 2.38
/// these were part of [`CAT_BAD`].
pub const CAT_ADULT: u64 = 16;
/// Category lists that say what a site is rather than that it attacks
/// visitors: ShadowWhisperer AI, Apple, Chat, DNS, Dynamic, Junk, Remote, Risk,
/// Shock, Top_Level, Tunnels, UrlShortener and Wild_*, the StevenBlack unified
/// hosts (adware and malware mixed), maltrail suspicious, OISD small and the
/// Block List Project redirect list. Before 2.38 these were part of [`CAT_BAD`].
pub const CAT_LISTED: u64 = 32;

/// Overlay OR-term for a category lookup. Expands to a literal `false` when the
/// `dynamic` feature is off, so the static read path is byte-identical to before.
macro_rules! dyn_cat_or {
    ($host:expr, $cat:expr) => {{
        #[cfg(feature = "dynamic")]
        {
            $crate::dynamic::dynamic_has_category($host, $cat)
        }
        #[cfg(not(feature = "dynamic"))]
        {
            false
        }
    }};
}

/// Overlay OR-term for an any-category lookup. `false` when the feature is off.
macro_rules! dyn_any_or {
    ($host:expr) => {{
        #[cfg(feature = "dynamic")]
        {
            $crate::dynamic::dynamic_contains($host)
        }
        #[cfg(not(feature = "dynamic"))]
        {
            false
        }
    }};
}

/// Unified FST Map (loaded from bytes generated in build.rs)
static FIREWALL_MAP: OnceLock<fst::Map<&'static [u8]>> = OnceLock::new();

#[inline]
fn firewall_map() -> &'static fst::Map<&'static [u8]> {
    FIREWALL_MAP
        .get_or_init(|| fst::Map::new(FIREWALL_FST_BYTES).expect("firewall fst invalid"))
}

/// True when `name` is a public suffix under an explicit rule in the ICANN
/// section of the PSL (`com.cn`, `co.uk`, `ad.jp`). False for private-section
/// suffixes (`amplifyapp.com`, dynamic DNS zones), for names that are a suffix
/// only through a wildcard rule (`coinbase-corp.fk` under `*.fk`), for unknown
/// TLDs and for anything registrable. Those stay blockable on purpose: feeds
/// list them to block free-hosting zones and real phishing domains.
#[inline]
pub(crate) fn is_explicit_icann_suffix(name: &str) -> bool {
    const PROBE: &[u8] = b"0--spider-psl-probe";
    const CAP: usize = 256;
    let bytes = name.as_bytes();
    let suffix = match psl::suffix(bytes) {
        Some(s) => s,
        None => return false,
    };
    if suffix.as_bytes().len() != bytes.len()
        || !suffix.is_known()
        || suffix.typ() != Some(psl::Type::Icann)
    {
        return false;
    }
    let parent = match name.find('.') {
        Some(dot) => &bytes[dot..],
        None => return true,
    };
    let len = PROBE.len() + parent.len();
    if len > CAP {
        return false;
    }
    let mut buf = [0u8; CAP];
    buf[..PROBE.len()].copy_from_slice(PROBE);
    buf[PROBE.len()..len].copy_from_slice(parent);
    let probe = &buf[..len];
    // An invented label under the same parent that is also a whole suffix
    // means the rule is a wildcard, not an explicit entry for `name`.
    match psl::suffix(probe) {
        Some(s) => s.as_bytes().len() != probe.len(),
        None => true,
    }
}

/// Check if host (or any parent domain) has the given category in the FST.
/// Walks up the domain hierarchy: "a.b.example.com" -> "b.example.com" -> "example.com",
/// stopping before an explicit ICANN public suffix ("x.sina.com.cn" tests
/// "x.sina.com.cn" and "sina.com.cn", never "com.cn").
#[inline]
fn fst_has_category(host: &str, cat: u64) -> bool {
    map_has_category(firewall_map(), host, cat)
}

/// The walk behind [`fst_has_category`], over any map, so tests can drive it
/// with a list that still carries a public-suffix entry.
#[inline]
fn map_has_category<D: AsRef<[u8]>>(map: &fst::Map<D>, host: &str, cat: u64) -> bool {
    let mut h = host;
    loop {
        // Never test a public suffix: a list entry for `com.cn` must not
        // refuse every site under it. Everything above it is a suffix too.
        if is_explicit_icann_suffix(h) {
            break;
        }
        if let Some(v) = map.get(h) {
            if v & cat != 0 {
                return true;
            }
        }
        // Move to the parent domain.
        match h.find('.') {
            Some(dot) => {
                h = &h[dot + 1..];
                // Stop if the remainder has no dot (bare TLD).
                if !h.contains('.') {
                    break;
                }
            }
            None => break,
        }
    }
    false
}

/// Get the hostname from a url.
pub fn get_host_from_url(url: &str) -> Option<&str> {
    let url = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    if let Some(pos) = url.find('/') {
        Some(&url[..pos])
    } else {
        Some(&url)
    }
}

pub fn is_bad_website_url(host: &str) -> bool {
    fst_has_category(host, CAT_BAD)
        || is_website_in_custom_set(host, &firewall::GLOBAL_BAD_WEBSITES)
        || dyn_cat_or!(host, CAT_BAD)
}

/// Listed by an adult content list. Not a threat verdict.
pub fn is_adult_website_url(host: &str) -> bool {
    fst_has_category(host, CAT_ADULT) || dyn_cat_or!(host, CAT_ADULT)
}

/// Listed by a category list (see [`CAT_LISTED`]). Not a threat verdict.
pub fn is_listed_website_url(host: &str) -> bool {
    fst_has_category(host, CAT_LISTED) || dyn_cat_or!(host, CAT_LISTED)
}

pub fn is_ad_website_url(host: &str) -> bool {
    fst_has_category(host, CAT_ADS)
        || is_website_in_custom_set(host, &firewall::GLOBAL_ADS_WEBSITES)
        || dyn_cat_or!(host, CAT_ADS)
}

pub fn is_tracking_website_url(host: &str) -> bool {
    fst_has_category(host, CAT_TRACKING)
        || is_website_in_custom_set(host, &firewall::GLOBAL_TRACKING_WEBSITES)
        || dyn_cat_or!(host, CAT_TRACKING)
}

pub fn is_gambling_website_url(host: &str) -> bool {
    fst_has_category(host, CAT_GAMBLING)
        || is_website_in_custom_set(host, &firewall::GLOBAL_GAMBLING_WEBSITES)
        || dyn_cat_or!(host, CAT_GAMBLING)
}

/// General networking blocking. At the moment you have to build this list yourself with the macro define_firewall!("networking", "a.ping.com").
pub fn is_networking_url(host: &str) -> bool {
    fst_has_category(host, CAT_BAD)
        || is_website_in_custom_set(host, &firewall::GLOBAL_BAD_WEBSITES)
        || is_website_in_custom_set(host, &firewall::GLOBAL_NETWORKING_WEBSITES)
        || dyn_cat_or!(host, CAT_BAD)
}

/// Determine a generic bad url.
pub fn is_url_bad(host: &str) -> bool {
    fst_contains_any(host)
        || is_website_in_custom_set(host, &firewall::GLOBAL_BAD_WEBSITES)
        || is_website_in_custom_set(host, &firewall::GLOBAL_ADS_WEBSITES)
        || is_website_in_custom_set(host, &firewall::GLOBAL_NETWORKING_WEBSITES)
        || is_website_in_custom_set(host, &firewall::GLOBAL_TRACKING_WEBSITES)
        || is_website_in_custom_set(host, &firewall::GLOBAL_GAMBLING_WEBSITES)
        || dyn_any_or!(host)
}

/// Check if host (or any parent domain) exists in the FST under any category.
#[inline]
fn fst_contains_any(host: &str) -> bool {
    let map = firewall_map();
    let mut h = host;
    loop {
        if is_explicit_icann_suffix(h) {
            break;
        }
        if map.contains_key(h) {
            return true;
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

/// Is the website in one of the custom sets.
fn is_website_in_custom_set(
    host: &str,
    set: &std::sync::OnceLock<&phf::Set<&'static str>>,
) -> bool {
    set.get().map(|s| s.contains(host)).unwrap_or(false)
}

/// The URL is in the bad list removing the URL http(s):// and paths.
pub fn is_bad_website_url_clean(host: &str) -> bool {
    get_host_from_url(host)
        .map(is_bad_website_url)
        .unwrap_or(false)
}

/// The URL is in the ads list.
pub fn is_ad_website_url_clean(host: &str) -> bool {
    get_host_from_url(host)
        .map(is_ad_website_url)
        .unwrap_or(false)
}

/// The URL is in the tracking list.
pub fn is_tracking_website_url_clean(host: &str) -> bool {
    get_host_from_url(host)
        .map(is_tracking_website_url)
        .unwrap_or(false)
}

/// The URL is in the networking list.
pub fn is_networking_website_url_clean(host: &str) -> bool {
    get_host_from_url(host)
        .map(is_networking_url)
        .unwrap_or(false)
}

/// The URL is in the gambling list.
pub fn is_gambling_website_url_clean(host: &str) -> bool {
    get_host_from_url(host)
        .map(is_gambling_website_url)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// IP blocking (feature = "ip")
//
// Known-bad IPv4 network ranges sourced from The Spamhaus Project DROP list
// (https://www.spamhaus.org/drop/), embedded at build time and matched via
// binary search. Used under the Spamhaus DROP terms (free for any use,
// attribution required). (c) The Spamhaus Project — https://www.spamhaus.org
// ---------------------------------------------------------------------------
#[cfg(feature = "ip")]
mod ip_block {
    // Defines `BAD_IP_RANGES_V4: &[(u32, u32)]` — sorted, non-overlapping inclusive ranges.
    include!(concat!(env!("OUT_DIR"), "/bad_ips.rs"));

    /// True if `ip` falls within any range. `ranges` must be sorted by start and
    /// non-overlapping (as emitted by build.rs).
    #[inline]
    pub(crate) fn ranges_contain(ranges: &[(u32, u32)], ip: u32) -> bool {
        match ranges.binary_search_by(|&(start, _)| start.cmp(&ip)) {
            Ok(_) => true,
            Err(0) => false,
            Err(i) => {
                let (start, end) = ranges[i - 1];
                start <= ip && ip <= end
            }
        }
    }

    #[inline]
    pub(crate) fn is_bad_ipv4(ip: u32) -> bool {
        ranges_contain(BAD_IP_RANGES_V4, ip)
    }
}

/// Returns true if the IP address falls within a known-bad network range
/// (e.g. Spamhaus DROP hijacked / cybercrime-leased netblocks).
///
/// IPv4 only at the moment; IPv6 addresses always return `false`.
#[cfg(feature = "ip")]
pub fn is_bad_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => ip_block::is_bad_ipv4(u32::from(v4)),
        std::net::IpAddr::V6(_) => false,
    }
}

/// Parse `ip` as an IP address and check it against the known-bad ranges.
/// Returns `false` if the string is not a valid IP address.
#[cfg(feature = "ip")]
pub fn is_bad_ip_str(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>()
        .map(is_bad_ip)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_bad_website_url_within_set() {
        let bad_website = "wingwahlau.com";
        assert!(is_bad_website_url(bad_website));
    }

    #[test]
    fn test_is_bad_website_url_not_in_set() {
        let good_website = "goodwebsite.com";
        assert!(!is_bad_website_url(good_website));
    }

    #[test]
    fn test_is_bad_website_url_empty_string() {
        assert!(!is_bad_website_url(""));
    }

    #[test]
    fn test_is_bad_website_url_case_sensitivity() {
        let bad_website = "10minutesto1.net";
        assert!(is_bad_website_url(bad_website.to_lowercase().as_str()));
    }

    #[test]
    fn test_is_ad_website_url() {
        assert!(is_ad_website_url("admob.google.com"));
        assert!(is_ad_website_url("ads.linkedin.com"));
    }

    #[test]
    fn test_is_tracking_website_url() {
        assert!(!is_tracking_website_url("2.atlasroofing.com"));
        assert!(is_tracking_website_url(
            "pixel.rubiconproject.net.akadns.net"
        ));
    }

    #[test]
    fn test_ning_com_whitelisted() {
        assert!(!is_bad_website_url("ning.com"), "ning.com should be whitelisted");
        assert!(!is_bad_website_url("competitiveintelligence.ning.com"), "subdomain of ning.com should be whitelisted");
    }

    #[test]
    fn test_adult_websites_categorized_not_hard_refused() {
        // Adult lists moved out of CAT_BAD in 2.38: still reported, and still
        // matched by is_url_bad, but no longer a threat verdict.
        for host in ["pornhub.com", "xvideos.com"] {
            assert!(is_adult_website_url(host), "{host} is on an adult list");
            assert!(is_url_bad(host), "{host} still matches the any-category check");
            assert!(!is_bad_website_url(host), "{host} is not a threat-feed entry");
        }
    }

    #[test]
    fn test_category_lists_are_not_hard_refused() {
        // www.veed.io is on ShadowWhisperer's AI list only.
        assert!(is_listed_website_url("www.veed.io"));
        assert!(!is_bad_website_url("www.veed.io"));
        assert!(!is_bad_website_url_clean("https://www.veed.io/ms-MY/peralatan"));
        // more.com is on ShadowWhisperer's Adult list by mistake, and is on the
        // whitelist, so it matches nothing at all.
        for host in ["more.com", "help-teller.more.com"] {
            assert!(!is_bad_website_url(host), "{host}");
            assert!(!is_adult_website_url(host), "{host}");
            assert!(!is_url_bad(host), "{host}");
        }
    }

    #[test]
    fn test_threat_feed_entries_still_hard_refused() {
        // zoominfo.com is on the Block List Project malware list (small tier)
        // and abuse list (medium tier), both threat feeds, so it stays refused.
        for host in [
            "zoominfo.com",
            "www.zoominfo.com",
            "wingwahlau.com",           // spider-rs/bad_websites
            "10minutesto1.net",         // Block List Project malware
            "buffooncountabletreble.com",
            "backspinreentryupright.com",
            "sub.backspinreentryupright.com",
        ] {
            assert!(is_bad_website_url(host), "{host} must stay a threat verdict");
        }
    }

    #[test]
    fn test_legit_websites_not_false_positive() {
        // Guard against false positives from the expanded porn/phishing sources.
        assert!(!is_bad_website_url("github.com"));
        assert!(!is_bad_website_url("wikipedia.org"));
        assert!(!is_bad_website_url("google.com"));
        // Platform roots that rejected candidate feeds listed outright, plus the
        // hosts allowlisted out of TweetFeed.
        for host in [
            "myshopify.com",
            "metamask.io",
            "etherscan.io",
            "r2.dev",
            "csiro.au",
            "pixeldrain.com",
            "submit-form.com",
            "kayoanime.com",
            "luckyprint52.ru",
        ] {
            assert!(!is_bad_website_url(host), "{host} hard-refused");
        }
    }

    #[test]
    fn test_trustpilot_whitelisted() {
        // trustpilot.com is whitelisted: BlockListProject's phishing/scam lists
        // include www.trustpilot.com, which is a false positive for a legit
        // review site. The whitelist walks up parent domains, so the www host
        // and any subdomain resolve as not-bad.
        assert!(!is_bad_website_url("trustpilot.com"), "trustpilot.com should be whitelisted");
        assert!(!is_bad_website_url("www.trustpilot.com"), "www.trustpilot.com should be whitelisted");
        assert!(!is_bad_website_url_clean("https://www.trustpilot.com/review/grey.co"), "trustpilot review URL should not be bad");
        assert!(!is_url_bad("www.trustpilot.com"), "trustpilot should not match any bad category");
    }

    #[test]
    fn test_usask_whitelisted() {
        // University of Saskatchewan is a legit institution swept into aggressive
        // phishing/scam feeds. The parent domain usask.ca is whitelisted, so the
        // apex and every subdomain (walked up to the parent) resolve as not-bad.
        assert!(!is_bad_website_url("usask.ca"), "usask.ca should be whitelisted");
        assert!(!is_bad_website_url("admissions.usask.ca"), "admissions.usask.ca should be whitelisted");
        assert!(!is_bad_website_url("medicine.usask.ca"), "medicine.usask.ca should be whitelisted");
        assert!(!is_url_bad("admissions.usask.ca"), "admissions.usask.ca should not match any bad category");
        assert!(!is_url_bad("medicine.usask.ca"), "medicine.usask.ca should not match any bad category");
        assert!(!is_bad_website_url_clean("https://admissions.usask.ca/programs"), "usask admissions URL should not be bad");
    }

    #[test]
    fn test_ai_vendors_whitelisted() {
        // Upstream feeds classify the major AI vendors as malicious, most likely
        // because recently registered AI domains trip "suspicious new domain"
        // heuristics. is_url_bad gates /scrape and /crawl, so this made every one
        // of them permanently uncrawlable.
        for host in [
            "openai.com",
            "chatgpt.com",
            "anthropic.com",
            "claude.ai",
            "huggingface.co",
            "ollama.com",
            "perplexity.ai",
            "labs.perplexity.ai", // parent-domain walk
            "stability.ai",
            "meta.ai",
            "openrouter.ai",
        ] {
            assert!(!is_bad_website_url(host), "{host} should be whitelisted");
            assert!(!is_url_bad(host), "{host} should not match any bad category");
        }
        assert!(
            !is_bad_website_url_clean("https://platform.openai.com/docs/api-reference"),
            "openai docs URL should not be bad"
        );
    }

    #[test]
    fn test_developer_tools_whitelisted_across_categories() {
        // These sat in the ads and tracking feeds rather than the bad-site feed,
        // so while the whitelist was applied to BAD only, adding them here had no
        // effect whatsoever. This test fails if that regresses: it asserts on
        // is_url_bad, which ORs ads and tracking in.
        for host in [
            "honeycomb.io",
            "instana.io",
            "honeybadger.io",
            "raygun.io",
            "airbrake.io",
            "backtrace.io",
            "canny.io",
            "plausible.io",
            "ipinfo.io",
            "ipgeolocation.io",
        ] {
            assert!(!is_url_bad(host), "{host} should not be refused by any category");
        }
        assert!(!is_ad_website_url("plausible.io"), "plausible.io is not an ad network");
        assert!(!is_tracking_website_url("honeycomb.io"), "honeycomb.io is observability, not tracking");
    }

    #[test]
    fn test_gambling_still_blocked() {
        // Whitelisting was extended to gambling for consistency, but nothing
        // gambling-related is whitelisted, so the category must still bite.
        // State lotteries and licensed operators stay blocked on purpose.
        assert!(is_url_bad("calottery.com"), "gambling must remain blocked");
        assert!(is_url_bad("bet9ja.com"), "gambling must remain blocked");
    }

    #[test]
    fn test_known_bad_still_blocked() {
        // Guards against the whitelist being widened until it stops meaning
        // anything. These are exactly the domain-generation-algorithm shapes the
        // firewall exists to catch.
        for host in ["buffooncountabletreble.com", "backspinreentryupright.com"] {
            assert!(is_url_bad(host), "{host} must stay blocked");
        }
    }

    #[test]
    fn test_abuse_prone_infrastructure_still_blocked() {
        // These are left blocked on purpose, with reasons listed next to the
        // whitelist in build.rs. They are easy to mistake for false positives
        // later because the companies behind them are legitimate, so pin them:
        // wildcard/dynamic DNS and shorteners launder phishing, and
        // packetstream resells residential bandwidth.
        for host in ["use-application-dns.net", "sslip.io", "packetstream.io", "short.io"] {
            assert!(is_url_bad(host), "{host} must stay blocked");
        }
    }

    #[test]
    fn test_ad_and_beacon_endpoints_still_blocked() {
        // Whitelisting reaches subresource blocking too, so real-time bidding and
        // fingerprinting endpoints stay blocked on purpose even though each is
        // run by a real company.
        for host in ["1rx.io", "bidr.io", "fpjs.io", "kameleoon.io"] {
            assert!(is_url_bad(host), "{host} must stay blocked");
        }
    }

    #[test]
    fn test_public_suffix_entries_do_not_block_their_zone() {
        // A malware feed lists `com.cn`. Before this fix every site under it
        // was refused, including the national portals.
        for host in [
            "www.sina.com.cn",
            "www.people.com.cn",
            "edu.china.com.cn",
            "static.cninfo.com.cn",
            "www.questmobile.com.cn",
            "www.mtkxjs.com.cn",
        ] {
            assert!(!is_bad_website_url(host), "{host} must not be refused by the com.cn entry");
            assert!(!is_url_bad(host), "{host} must not match any category");
        }
        assert!(!is_bad_website_url_clean("https://www.sina.com.cn/news"));
    }

    #[test]
    fn test_listed_hosts_under_a_public_suffix_still_blocked() {
        // Children of `com.cn` were pruned while `com.cn` itself was listed.
        // With the suffix entry dropped before the prune they are kept.
        for host in [
            "cn-oyi-okx.com.cn",      // phishing feed
            "download-sougou.com.cn", // urlhaus malware feed
            "b86-telegram.com.cn",    // phishing feed
        ] {
            assert!(is_bad_website_url(host), "{host} must stay blocked");
            let sub = format!("login.{host}");
            assert!(is_bad_website_url(&sub), "{sub} must stay blocked");
        }
    }

    #[test]
    fn test_private_and_wildcard_suffix_listings_still_block() {
        // PSL private-section zones (free hosting, dynamic DNS) and names that
        // are suffixes only through a wildcard rule are listed on purpose.
        for host in [
            "coinbase-corp.fk",
            "login.coinbase-corp.fk",
            "googlecom.mm",
            "anything.amplifyapp.com",
        ] {
            assert!(is_bad_website_url(host), "{host} must stay blocked");
        }
        // And the plain subdomain walk still reaches a listed registrable domain.
        assert!(is_bad_website_url("a.b.wingwahlau.com"));
    }

    #[test]
    fn test_walk_skips_a_public_suffix_entry_even_if_present() {
        // The build drops suffix entries; the walk also refuses to test one,
        // so a list that still carries `com.cn` cannot block the zone.
        let map = fst::Map::from_iter(vec![("com.cn", CAT_BAD), ("evil.com.cn", CAT_BAD)]).unwrap();
        assert!(!map_has_category(&map, "www.sina.com.cn", CAT_BAD));
        assert!(map_has_category(&map, "evil.com.cn", CAT_BAD));
        assert!(map_has_category(&map, "a.evil.com.cn", CAT_BAD));
        let map = fst::Map::from_iter(vec![("amplifyapp.com", CAT_BAD)]).unwrap();
        assert!(map_has_category(&map, "x.amplifyapp.com", CAT_BAD), "private suffix entries still block");
    }

    #[test]
    fn test_is_explicit_icann_suffix() {
        for s in ["com.cn", "co.uk", "com.au", "gov.cn", "co.tz", "ad.jp", "cn"] {
            assert!(is_explicit_icann_suffix(s), "{s}");
        }
        for s in [
            "sina.com.cn",
            "bbc.co.uk",
            "amplifyapp.com",
            "blogspot.com",
            "coinbase-corp.fk",
            "googlecom.mm",
            "",
        ] {
            assert!(!is_explicit_icann_suffix(s), "{s}");
        }
        let long = format!("{}.com.cn", "a".repeat(300));
        assert!(!is_explicit_icann_suffix(&long));
    }

    #[test]
    fn test_define_firewall_macro() {
        define_firewall!("ads", "adwebsite.com", "ad1website.com");

        assert!(is_ad_website_url("adwebsite.com"));
        assert!(is_ad_website_url("ad1website.com"));

        define_firewall!("gambling", "gamblingwebsite.com");

        assert!(is_gambling_website_url("gamblingwebsite.com"));

        define_firewall!("global", "anotherbadwebsite.com", "chrome:/");
        assert!(is_bad_website_url("anotherbadwebsite.com"));
        assert!(is_bad_website_url("chrome:/"));
    }

    #[cfg(feature = "ip")]
    #[test]
    fn test_ip_ranges_contain() {
        // 10.0.0.0/24 -> [167772160, 167772415]; 192.168.1.0/30 -> [3232235776, 3232235779]
        let ranges = &[(167772160u32, 167772415u32), (3232235776u32, 3232235779u32)];
        assert!(super::ip_block::ranges_contain(ranges, 167772160)); // 10.0.0.0 (start)
        assert!(super::ip_block::ranges_contain(ranges, 167772415)); // 10.0.0.255 (end)
        assert!(super::ip_block::ranges_contain(ranges, 167772300)); // inside
        assert!(!super::ip_block::ranges_contain(ranges, 167772416)); // 10.0.1.0 (just past)
        assert!(!super::ip_block::ranges_contain(ranges, 167772159)); // 9.255.255.255 (just before)
        assert!(super::ip_block::ranges_contain(ranges, 3232235778)); // 192.168.1.2 (second range)
        assert!(!super::ip_block::ranges_contain(ranges, 0)); // below all
        assert!(!super::ip_block::ranges_contain(ranges, u32::MAX)); // above all
    }

    #[cfg(feature = "ip")]
    #[test]
    fn test_is_bad_ip_str() {
        // Invalid / non-IP inputs are safe.
        assert!(!is_bad_ip_str("not-an-ip"));
        assert!(!is_bad_ip_str(""));
        // Private space is never in Spamhaus DROP.
        assert!(!is_bad_ip("10.0.0.1".parse().unwrap()));
        // IPv6 is currently always false.
        assert!(!is_bad_ip("::1".parse().unwrap()));
    }
}
