# Spider Firewall — Weekly Blocklist Research Report
**Date:** 2026-07-06  
**Verdict: No new sources added this week** — no candidate passed all four hard gates (format, commercial license, freshness ≤ 3 months, low CDN/cloud FP risk) with full independent verification.

---

## Already-Aggregated Sources (verified current as of 2026-07-06)

### Domain / Hosts feeds
| Tier | Source | Category |
|------|--------|----------|
| small | ShadowWhisperer/BlockLists | bad/ads/tracking/gambling |
| small | badmojr/1Hosts Lite | ads/tracking |
| small | spider-rs/bad_websites | bad |
| small | StevenBlack/hosts | bad |
| small | StevenBlack/hosts alternates/porn | bad |
| small | blocklistproject malware-nl.txt | bad |
| small | blocklistproject phishing-nl.txt | bad |
| small | blocklistproject scam-nl.txt | bad |
| small | malware-filter urlhaus-filter-domains.txt | bad |
| small | malware-filter phishing-filter-hosts.txt | bad |
| medium | blocklistproject ransomware-nl.txt | bad |
| medium | blocklistproject fraud-nl.txt | bad |
| medium | blocklistproject abuse-nl.txt | bad |
| medium | mitchellkrogza/Phishing.Database ACTIVE | bad |
| medium | stamparm/maltrail suspicious domains | bad |
| medium | phishdestroy/destroylist primary active | bad |
| medium | durablenapkin/scamblocklist | bad |
| medium | hagezi/dns-blocklists tif.mini-onlydomains | bad |
| medium | abuse.ch ThreatFox hostfile | bad |
| large | blocklistproject redirect-nl.txt | bad |
| large | blocklistproject tracking-nl.txt | tracking |
| large | blocklistproject ads-nl.txt | ads |
| large | hagezi/dns-blocklists tif-onlydomains | bad |
| large | URLhaus full hostfile | bad |

### IP / CIDR feeds (feature = `ip`)
| Tier | Source | Category |
|------|--------|----------|
| any | Spamhaus DROP (now includes former EDROP) | hijacked netblocks |
| any | abuse.ch Feodo Tracker ipblocklist.txt | botnet C2 IPs |
| medium | elliotwutingfeng/ThreatFox-IOC-IPs | malware C2/distribution IPs |
| large | malware-filter urlhaus-filter-dnscrypt-blocked-ips | malware-hosting IPs |

---

## Domain Feed Candidates Evaluated

### 1. Phishing.Army
- **Feed URL:** `https://phishing.army/download/phishing_army_blocklist.txt`
- **Format:** Plain domain list (one domain per line) ✓
- **License:** CC BY-NC 4.0 — **NonCommercial, commercial use prohibited**
- **Cadence:** Every 6 hours; actively maintained ✓
- **Upstreams:** PhishTank, OpenPhish, Cert.pl, Phishunt.io, URLscan.io, PhishFindR
- **FP risk:** Low ✓
- **Verdict: EXCLUDED** — CC BY-NC 4.0 is a hard disqualifier for a commercial product.

### 2. DigitalSide Threat Intelligence
- **Feed URL:** `https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestdomains.txt`
- **Format:** Plain domain list (one domain per line) ✓
- **License:** MIT — commercial use permitted ✓
- **Cadence:** GitHub mirror last updated **October 18, 2024** (~21 months stale). The live `osint.digitalside.it` endpoint returned HTTP 403 to automated access.
- **FP risk:** Low ✓
- **Verdict: EXCLUDED** — exceeds the 3-month freshness gate. Live server blocks automated access making build-time fetching unreliable regardless.

### 3. botvrij.eu Domain IOCs
- **Feed URLs:** `https://www.botvrij.eu/data/ioclist.domain.raw`, `ioclist.hostname.raw`
- **Format:** Plain domain/hostname list ✓
- **License:** Custom "no resale" clause — "You cannot resell the data." Not a recognized FOSS license; commercial internal use is likely permitted, but redistribution as a packaged feed is prohibited. Legal review required.
- **Cadence:** Claims daily updates via MISP; live freshness could not be independently confirmed from automated access.
- **FP risk:** Low (APT/threat-intel curated) ✓
- **Verdict: EXCLUDED** — non-standard license requires legal sign-off not appropriate for an automated weekly addition. Freshness unverifiable.

### 4. NoCoin filter lists
- **`nicehash/NoCoin`:** Repository does not exist (HTTP 404). Dead.
- **`hoshsadiq/adblock-nocoin-list` hosts.txt:** MIT license ✓; format is hosts-file ✓; last commit **March 5, 2025** (~16 months stale).
- **Verdict: EXCLUDED** — primary repo is gone; the best-known alternative is stale. The in-browser cryptojacking threat has also substantially declined since 2018–2019.

### 5. RPiList/specials (German phishing/scam)
- **Format:** Adblock Plus syntax (`||domain^`) — not plain domain or hosts format
- **License:** CC BY-NC 4.0 — **NonCommercial, commercial use prohibited**
- **Cadence:** Daily, actively maintained ✓
- **Verdict: EXCLUDED** — CC BY-NC 4.0. Wrong format is a secondary disqualifier.

### 6. DNS-BH Malware Domain Blocklist (malwaredomains.com)
- **Status:** Project shut down ~2016–2017. Domain may still resolve but no data updates. URLhaus (already in build.rs at small and large tier) is the accepted successor.
- **Verdict: EXCLUDED** — defunct.

### 7. abuse.ch SSLBL domain/IP feeds
- SSLBL is SSL-certificate and TLS-fingerprint based; no viable domain feed exists.
- The Feodo Tracker domain blocklist endpoint returns "No present data" — Feodo tracks C2 by IP address, not domain.
- The `abuse.ch ThreatFox` domain hostfile (already in build.rs at medium tier) covers the domain-based abuse.ch feed.
- **Verdict: EXCLUDED / ALREADY COVERED.**

### 8. OpenPhish Community Feed
- **Format:** Full URLs (e.g., `https://domain.tld/path/`) — **NOT bare domains**; incompatible with `parse_domain_lines()` or `parse_hosts_lines()`.
- **License:** Non-commercial use only.
- **Entry count:** ~800 entries in a 7-day rolling window (very small).
- **Verdict: EXCLUDED** — non-commercial license AND wrong format.

### 9. mitchellkrogza/Phishing.Database (ALL variant)
- The ACTIVE-only variant (`phishing-domains-ACTIVE.txt`) is already in build.rs at medium tier.
- The ALL-domains variant (`phish.co.za/latest/ALL-phishing-domains.lst`, ~496K entries) includes INACTIVE and INVALID domains — high FP risk as recycled domains become legitimate.
- **Verdict: EXCLUDED** — high FP risk. ACTIVE variant already included.

### 10. malware-filter additional feeds (pup-filter, botnet-filter)
- **pup-filter:** Upstream data is "All rights reserved by Zhouhan Chen" — proprietary. The MIT wrapper covers code only, not data.
- **botnet-filter:** IP-address based (AdGuard Home IP format), not a domain feed. IP coverage from Feodo/ThreatFox already in build.rs.
- **Verdict: EXCLUDED** — proprietary upstream (pup-filter); not a domain feed (botnet-filter).

### 11. Spam404 main-blacklist.txt
- **Feed URL:** `https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt`
- **Format:** Bare domain list (one domain per line) ✓
- **License:** CC BY-SA 4.0 — commercial use is permitted, but the **ShareAlike clause** requires derivatives to be distributed under the same license. Embedding this data into a compiled FST map that ships in a proprietary commercial product is legally grey; the ShareAlike requirement likely extends to the compiled artifact.
- **Last commit to main-blacklist.txt:** September 17, 2025 (~10 months stale).
- **Verdict: EXCLUDED** — stale (exceeds 3-month freshness gate) AND ShareAlike poses downstream licensing risk for a commercial compiled product.

### 12. CERT.PL phishing domains (hole.cert.pl)
- **Feed URL:** `https://hole.cert.pl/domains/domains.txt`
- **Format:** Plain domain list ✓
- **License:** Not independently verified (unable to reach the terms page).
- **Server access:** Returns HTTP 403 to automated access — not suitable for build-time fetching.
- **Verdict: EXCLUDED** — server blocks automated access; build-time fetch would fail silently with no entries.

---

## IP / CIDR Feed Candidates Evaluated

### 1. Spamhaus EDROP
- **Status:** Merged into main Spamhaus DROP on **April 10, 2024**. The edrop.txt URL now returns only the comment: `; This list has been merged into https://www.spamhaus.org/drop/drop.txt`
- **Impact:** Already covered by the existing `drop.txt` fetch in build.rs.
- **Verdict: N/A** — no longer a separate list.

### 2. abuse.ch SSLBL Botnet C2 IP Blacklist
- **Status:** **Deprecated January 3, 2025**. Both `sslipblacklist.txt` and `sslipblacklist_aggressive.txt` were retired. abuse.ch consolidated botnet C2 IP tracking under Feodo Tracker, which is already in build.rs.
- **Verdict: EXCLUDED** — deprecated. Replacement (Feodo Tracker) already included.

### 3. IPsum (stamparm/ipsum)
- **Feed URLs:** `https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt` (count ≥ 3), levels 1–8 available.
- **Format:** `levels/N.txt` files contain bare IPs one per line ✓. The base `ipsum.txt` is tab-separated (IP + count).
- **License:** The Unlicense (public domain) — commercial use explicitly permitted ✓
- **Cadence:** Daily, updated as of July 6, 2026 ✓
- **Entry count:** ~14,743 IPs at level ≥ 3; ~5,000–7,000 IPs at level ≥ 5.
- **FP risk: HIGH** — direct inspection of `levels/3.txt` confirmed the presence of AWS (3.x, 13.x, 18.x, 34.x, 52.x, 54.x), Microsoft Azure (20.x, 40.x), and Google Cloud (34.x, 35.x) IP ranges. The README explicitly warns that it includes Shodan, Censys, and cloud provider IPs. For a web crawler that fetches many legitimate AWS/GCP/Azure-hosted sites, blocking these ranges is catastrophic.
- **Verdict: EXCLUDED** — confirmed cloud/CDN IP presence at all practical threshold levels. Hard disqualification for a crawler-oriented firewall.

### 4. GreenSnow Blocklist
- **Feed URL:** `http://blocklist.greensnow.co/greensnow.txt`
- **Format:** Bare IPv4 addresses, one per line ✓
- **License:** "Copyright © 2013-2026 GreenSnow.co. All rights reserved. Reproduction or republication strictly prohibited." No commercial license grant. Third-party documentation states commercial incorporators must contact GreenSnow for a commercial permit.
- **Cadence:** Every 30 minutes; ~5,458 IPs as of July 6, 2026 ✓
- **FP risk:** Low–Moderate (individual attack IPs, no CDN/cloud ranges) ✓
- **Verdict: EXCLUDED** — "All rights reserved" with no explicit commercial grant is a hard disqualifier.

### 5. DataPlane.org feeds (sshpwauth, sipquery, etc.)
- **Format:** Pipe-delimited CSV (ASN | country | timestamp | IP | …) — NOT plain IP per line
- **License:** "Free for non-commercial use only" — explicit NonCommercial restriction
- **Cadence:** Daily ✓
- **FP risk:** Low (individual attack-source IPs, no CDN ranges) ✓
- **Verdict: EXCLUDED** — NonCommercial license AND wrong format.

### 6. StopForumSpam toxic IPs
- **Format:** Zipped plain IPs (requires unzip step, not a bare .txt URL)
- **License:** "Non-commercial — you will not charge money for any software that utilizes the data." Hard commercial prohibition.
- **Verdict: EXCLUDED** — NonCommercial license.

### 7. FireHOL Level 1
- **Feed URL:** `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset`
- **Format:** CIDR subnets, one per line ✓
- **Aggregates:** Spamhaus DROP + Feodo Tracker + fullbogons (unallocated/reserved space) + DShield top-20 attacking /24s
- **Entry count:** 3,867 subnets covering **611,169,345 unique IPs**
- **License:** Mixed — GPL scripts (firehol), DShield (non-commercial attribution required for commercial use), Feodo CC0, Spamhaus DROP terms
- **FP risk: HIGH** — the `fullbogons` component (from Team Cymru) blocks all unallocated and newly-allocated IP space; appropriate for BGP null-routing but would incorrectly block legitimate newly-allocated IPs at the application layer. The 611M IP footprint is far too aggressive for a web crawler.
- Also: Spamhaus DROP and Feodo Tracker are already in build.rs — the only net-new content would be DShield top-20 /24s and fullbogons.
- **Verdict: EXCLUDED** — catastrophic FP risk (fullbogons at application layer), mixed commercial licensing, mostly duplicates existing sources.

### 8. CINS Score / CI Army (cinsscore.com)
- **Feed URL:** `http://cinsscore.com/list/ci-badguys.txt`
- **Format:** Bare IPs, one per line ✓
- **License:** No formal license. Described informally as "free for the community" and "you can parse and use in any way you see fit." No CC, MIT, or public domain declaration. "Free for community" is not a recognized commercial license grant.
- **Cadence:** Hourly ✓
- **FP risk:** Low–Moderate ✓
- **Verdict: EXCLUDED** — no formal license; cannot be verified as commercially permitted. A formal commercial use clarification from Nomic Networks (info@sentinelips.com) would be required before inclusion.

### 9. Binary Defense Artillery Threat Intelligence Feed
- **Feed URL:** `https://www.binarydefense.com/banlist.txt`
- **License:** "May not be used for commercial resale or in products that are charging fees for such services." Explicit commercial prohibition.
- **Verdict: EXCLUDED** — commercial use explicitly prohibited.

### 10. Proofpoint Emerging Threats `compromised-ips.txt`
- **Feed URL:** `http://rules.emergingthreats.net/blockrules/compromised-ips.txt`
- **Format:** Bare IPv4 addresses, one per line — confirmed via firehol mirror (`et_compromised.ipset`, July 2, 2026) ✓
- **License:** BSD (Proofpoint / Emerging Threats) — commercial use permitted ✓ (reported by multiple independent sources; direct read of license header blocked by proxy)
- **Cadence:** Every 12 hours; last confirmed active July 2, 2026 ✓
- **Entry count:** 628 unique IPs ✓ (small; specific confirmed-compromised hosts)
- **FP risk:** Low ✓ — specifically identified compromised infrastructure from Proofpoint research; no CDN/cloud ranges expected
- **Threat class:** Compromised legitimate servers repurposed for attack infrastructure — distinct from botnet C2 IPs (Feodo/ThreatFox) and hijacked netblocks (Spamhaus DROP)
- **Server access concern:** The primary URL returned HTTP 403 from this proxy environment. This may be proxy-specific (the build.rs `ua_generator::ua::spoof_ua()` spoofing may succeed in a real build environment); `fetch_text_opt` would make any failure non-fatal. The firehol mirror (`raw.githubusercontent.com/firehol/blocklist-ipsets/master/et_compromised.ipset`) IS accessible and correctly parsed by `parse_cidr_v4_lines` (uses `#` comment prefix).
- **Verdict: QUALIFIED CANDIDATE — not added this run** due to: (1) primary URL inaccessible from this proxy, license not directly read; (2) very small entry count (628 IPs); (3) unable to run `cargo build` verification in this environment. Recommend manual verification of URL accessibility and BSD license header in the next maintenance cycle before adding.

### 11. AlienVault OTX Reputation Feed
- **Format:** IP + metadata fields — NOT plain IP per line
- **License:** OTX pulse contributions are CC BY-NC-SA by default — NonCommercial
- **FP risk: HIGH** — community-sourced; cloud/CDN IPs (Cloudflare, AWS, Google) appear regularly in OTX pulses due to attacker abuse of shared infrastructure
- **Server access:** Legacy `reputation.alienvault.com` endpoint appears deprecated/gated
- **Verdict: EXCLUDED** — NC license, high FP risk, broken endpoint.

### 12. Blocklist.de
- **Feed URL:** `http://lists.blocklist.de/lists/all.txt`
- **Format:** Bare IPv4 addresses, one per line ✓ (~24,297 IPs, rolling 48h window)
- **License:** Described as "free and voluntary service." No explicit CC or OSI license published. Terms page (`/en/terms.html`) returned HTTP 403 from this proxy environment — license could not be directly verified.
- **Cadence:** Rolling 48-hour window, near-real-time ✓
- **FP risk:** Moderate — fail2ban-aggregated IPs; no CDN/cloud ranges (individual attack-source IPs) ✓
- **Verdict: EXCLUDED this run** — commercial license could not be verified. Widely adopted in commercial security products (CrowdSec, IPFire), suggesting permissive community use, but the formal terms are required per the commercial license hard gate. Recommend visiting `www.blocklist.de/en/terms.html` directly to confirm commercial use permissions in the next cycle.

---

## Summary

| Candidate | Format | Commercial License | Freshness | FP Risk | Verdict |
|-----------|--------|--------------------|-----------|---------|---------|
| Phishing.Army (domains) | ✓ plain domains | ✗ CC BY-NC 4.0 | ✓ 6h | ✓ low | EXCLUDED — NC license |
| DigitalSide Threat Intel (domains) | ✓ plain domains | ✓ MIT | ✗ 21 months stale | ✓ low | EXCLUDED — stale |
| botvrij.eu (domains) | ✓ plain domains | ✗ custom "no resale" | ? | ✓ low | EXCLUDED — unclear license |
| NoCoin (hoshsadiq) hosts.txt | ✓ hosts-file | ✓ MIT | ✗ 16 months stale | ✓ low | EXCLUDED — stale |
| RPiList/specials | ✗ ABP syntax | ✗ CC BY-NC 4.0 | ✓ daily | ✓ low | EXCLUDED — NC + wrong format |
| malwaredomains.com | N/A | N/A | ✗ defunct ~2016 | N/A | EXCLUDED — defunct |
| abuse.ch SSLBL (domains) | N/A | ✓ CC0 | N/A | N/A | EXCLUDED — no domain feed |
| OpenPhish community | ✗ full URLs | ✗ NonCommercial | ✓ 12h | ✓ low | EXCLUDED — NC + wrong format |
| mitchellkrogza ALL-domains | ✓ plain domains | ✓ MIT | ✓ daily | ✗ high (INACTIVE+INVALID) | EXCLUDED — FP risk |
| pup-filter | ✓ plain domains | ✗ proprietary upstream | ✓ 2×/day | ✓ low | EXCLUDED — proprietary data |
| Spam404 main-blacklist.txt | ✓ plain domains | ⚠ CC BY-SA (ShareAlike risk) | ✗ 10 months stale | ✓ low | EXCLUDED — stale + ShareAlike |
| CERT.PL domains | ✓ plain domains | ? unverified | ✓ daily | ✓ low | EXCLUDED — 403 automated access |
| Spamhaus EDROP | N/A (merged into DROP) | ✓ | ✓ | ✓ | N/A — merged Apr 2024 |
| abuse.ch SSLBL IPs | N/A (deprecated) | ✓ CC0 | ✗ deprecated Jan 2025 | N/A | EXCLUDED — deprecated |
| IPsum level ≥ 3 | ✓ bare IPs | ✓ Unlicense | ✓ daily | ✗ HIGH (AWS/GCP/Azure confirmed) | EXCLUDED — CDN/cloud FP risk |
| GreenSnow IPs | ✓ bare IPs | ✗ All rights reserved | ✓ 30 min | ✓ low–mod | EXCLUDED — no license grant |
| DataPlane.org IPs | ✗ pipe-delimited CSV | ✗ NonCommercial | ✓ daily | ✓ low | EXCLUDED — NC + wrong format |
| StopForumSpam IPs | ✗ zipped | ✗ NonCommercial | ✓ daily | ✓ low–mod | EXCLUDED — NC + wrong format |
| FireHOL Level 1 | ✓ CIDR/line | ✗ mixed licenses | ✓ daily | ✗ HIGH (611M IPs) | EXCLUDED — FP + license |
| CINS Score IPs | ✓ bare IPs | ✗ no formal license | ✓ hourly | ✓ low–mod | EXCLUDED — unverifiable license |
| Binary Defense IPs | ✓ bare IPs | ✗ commercial prohibited | ? | ? | EXCLUDED — NC license |
| Emerging Threats compromised-ips.txt | ✓ bare IPs | ✓ BSD (unread directly) | ✓ 12h | ✓ low | QUALIFIED CANDIDATE — server 403, unrun |
| AlienVault OTX | ✗ IP + metadata | ✗ CC BY-NC-SA | ? broken | ✗ HIGH (CDN FPs) | EXCLUDED — NC + FP risk |
| Blocklist.de IPs | ✓ bare IPs | ? unconfirmed | ✓ 48h rolling | ✓ moderate | EXCLUDED this run — license unverified |

---

## Next Cycle Recommendations

Two sources are worth revisiting when their unresolved issues can be addressed:

1. **Emerging Threats `compromised-ips.txt`** (`http://rules.emergingthreats.net/blockrules/compromised-ips.txt`): Verify that the URL is accessible from a real build environment (the 403 may be proxy-specific); directly read the BSD license header in the file to confirm commercial terms. If both check out, add at `ip` + small tier using `fetch_text_opt`. Entry count is small (628 IPs) but the threat class (compromised legitimate hosts used as attack infrastructure) is complementary to existing sources.

2. **Blocklist.de** (`http://lists.blocklist.de/lists/all.txt`): Directly read `www.blocklist.de/en/terms.html` in a non-proxied environment to confirm commercial use is permitted. If confirmed, add at `ip` + medium tier using `fetch_text_opt`. Threat class (brute-force/scan attack-source IPs, rolling 48h window) would add ~24K IPs not covered by existing hijacked-netblock or confirmed-C2 sources.

---

*Generated by weekly maintenance agent run on 2026-07-06.*
