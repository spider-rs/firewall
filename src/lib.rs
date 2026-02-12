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

/// Category bitmask flags — must stay in sync with build.rs.
const CAT_BAD: u64 = 1;
const CAT_ADS: u64 = 2;
const CAT_TRACKING: u64 = 4;
const CAT_GAMBLING: u64 = 8;

/// Unified FST Map (loaded from bytes generated in build.rs)
static FIREWALL_MAP: OnceLock<fst::Map<&'static [u8]>> = OnceLock::new();

#[inline]
fn firewall_map() -> &'static fst::Map<&'static [u8]> {
    FIREWALL_MAP
        .get_or_init(|| fst::Map::new(FIREWALL_FST_BYTES).expect("firewall fst invalid"))
}

/// Check if host (or any parent domain) has the given category in the FST.
/// Walks up the domain hierarchy: "a.b.example.com" -> "b.example.com" -> "example.com".
#[inline]
fn fst_has_category(host: &str, cat: u64) -> bool {
    let map = firewall_map();
    let mut h = host;
    loop {
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
}

pub fn is_ad_website_url(host: &str) -> bool {
    fst_has_category(host, CAT_ADS)
        || is_website_in_custom_set(host, &firewall::GLOBAL_ADS_WEBSITES)
}

pub fn is_tracking_website_url(host: &str) -> bool {
    fst_has_category(host, CAT_TRACKING)
        || is_website_in_custom_set(host, &firewall::GLOBAL_TRACKING_WEBSITES)
}

pub fn is_gambling_website_url(host: &str) -> bool {
    fst_has_category(host, CAT_GAMBLING)
        || is_website_in_custom_set(host, &firewall::GLOBAL_GAMBLING_WEBSITES)
}

/// General networking blocking. At the moment you have to build this list yourself with the macro define_firewall!("networking", "a.ping.com").
pub fn is_networking_url(host: &str) -> bool {
    fst_has_category(host, CAT_BAD)
        || is_website_in_custom_set(host, &firewall::GLOBAL_BAD_WEBSITES)
        || is_website_in_custom_set(host, &firewall::GLOBAL_NETWORKING_WEBSITES)
}

/// Determine a generic bad url.
pub fn is_url_bad(host: &str) -> bool {
    fst_contains_any(host)
        || is_website_in_custom_set(host, &firewall::GLOBAL_BAD_WEBSITES)
        || is_website_in_custom_set(host, &firewall::GLOBAL_ADS_WEBSITES)
        || is_website_in_custom_set(host, &firewall::GLOBAL_NETWORKING_WEBSITES)
        || is_website_in_custom_set(host, &firewall::GLOBAL_TRACKING_WEBSITES)
        || is_website_in_custom_set(host, &firewall::GLOBAL_GAMBLING_WEBSITES)
}

/// Check if host (or any parent domain) exists in the FST under any category.
#[inline]
fn fst_contains_any(host: &str) -> bool {
    let map = firewall_map();
    let mut h = host;
    loop {
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
}
