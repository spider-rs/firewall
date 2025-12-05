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
    #[macro_export]
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

// Utilize the OnceLock sets within functions
pub fn is_bad_website_url(host: &str) -> bool {
    BAD_WEBSITES.contains(&host) || is_website_in_custom_set(&host, &firewall::GLOBAL_BAD_WEBSITES)
}

pub fn is_ad_website_url(host: &str) -> bool {
    ADS_WEBSITES.contains(&host) || is_website_in_custom_set(&host, &firewall::GLOBAL_ADS_WEBSITES)
}

pub fn is_tracking_website_url(host: &str) -> bool {
    TRACKING_WEBSITES.contains(&host)
        || is_website_in_custom_set(&host, &firewall::GLOBAL_TRACKING_WEBSITES)
}

pub fn is_gambling_website_url(host: &str) -> bool {
    GAMBLING_WEBSITES.contains(&host)
        || is_website_in_custom_set(&host, &firewall::GLOBAL_GAMBLING_WEBSITES)
}

// General networking blocking. At the moment you have to build this list yourself with the macro define_firewall!("networking", "a.ping.com").
pub fn is_networking_url(host: &str) -> bool {
    BAD_WEBSITES.contains(&host)
        || is_website_in_custom_set(&host, &firewall::GLOBAL_BAD_WEBSITES)
        || is_website_in_custom_set(&host, &firewall::GLOBAL_NETWORKING_WEBSITES)
}

/// Is the website in one of the custom sets.
fn is_website_in_custom_set(
    host: &str,
    set: &std::sync::OnceLock<&phf::Set<&'static str>>,
) -> bool {
    if let Some(set) = set.get() {
        set.contains(host)
    } else {
        false
    }
}

/// The URL is in the bad list removing the URL http(s):// and paths.
pub fn is_bad_website_url_clean(host: &str) -> bool {
    if let Some(host) = get_host_from_url(host) {
        is_bad_website_url(&host)
    } else {
        false
    }
}

/// The URL is in the ads list.
pub fn is_ad_website_url_clean(host: &str) -> bool {
    if let Some(host) = get_host_from_url(host) {
        is_ad_website_url(&host)
    } else {
        false
    }
}

/// The URL is in the tracking list.
pub fn is_tracking_website_url_clean(host: &str) -> bool {
    if let Some(host) = get_host_from_url(host) {
        is_tracking_website_url(&host)
    } else {
        false
    }
}

/// The URL is in the networking list.
pub fn is_networking_website_url_clean(host: &str) -> bool {
    if let Some(host) = get_host_from_url(host) {
        is_networking_url(&host)
    } else {
        false
    }
}

/// The URL is in the gambling list.
pub fn is_gambling_website_url_clean(host: &str) -> bool {
    if let Some(host) = get_host_from_url(host) {
        is_gambling_website_url(&host)
    } else {
        false
    }
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
        assert!(is_tracking_website_url("2.atlasroofing.com"));
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

        define_firewall!("unknown", "anotherbadwebsite.com");
        assert!(is_bad_website_url("anotherbadwebsite.com"));

        define_firewall!("global", "chrome:/");
        assert!(is_ad_website_url("chrome://about"));
    }
}
