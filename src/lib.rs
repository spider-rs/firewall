include!(concat!(env!("OUT_DIR"), "/bad_websites.rs"));

/// The url is in the bad list.
pub fn is_bad_website_url(host: &str) -> bool {
    BAD_WEBSITES.contains(&host)
}

/// The url is in the ads list.
pub fn is_ad_website_url(host: &str) -> bool {
    ADS_WEBSITES.contains(&host)
}

/// The url is in the tracking list.
pub fn is_tracking_website_url(host: &str) -> bool {
    TRACKING_WEBSITES.contains(&host)
}

/// The url is in the gambling list.
pub fn is_gambling_website_url(host: &str) -> bool {
    GAMBLING_WEBSITES.contains(&host)
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
        let bad_website = "admob.google.com";
        assert!(is_ad_website_url(bad_website.as_str()));
    }

    #[test]
    fn test_is_tracking_website_url() {
        let bad_website = "2.atlasroofing.com";
        assert!(is_tracking_website_url(bad_website.as_str()));
    }
}
