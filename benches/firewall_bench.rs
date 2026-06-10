use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spider_firewall::*;

fn bench_is_bad_website_url(c: &mut Criterion) {
    c.bench_function("is_bad_website_url (hit)", |b| {
        b.iter(|| is_bad_website_url(black_box("wingwahlau.com")))
    });
    c.bench_function("is_bad_website_url (miss)", |b| {
        b.iter(|| is_bad_website_url(black_box("goodwebsite.com")))
    });
    // Deep subdomain miss — exercises the parent walk-up worst case.
    c.bench_function("is_bad_website_url (deep miss)", |b| {
        b.iter(|| is_bad_website_url(black_box("a.b.c.d.goodwebsite.com")))
    });
}

fn bench_is_ad_website_url(c: &mut Criterion) {
    c.bench_function("is_ad_website_url (hit)", |b| {
        b.iter(|| is_ad_website_url(black_box("admob.google.com")))
    });
    c.bench_function("is_ad_website_url (miss)", |b| {
        b.iter(|| is_ad_website_url(black_box("google.com")))
    });
}

fn bench_is_url_bad(c: &mut Criterion) {
    c.bench_function("is_url_bad (hit)", |b| {
        b.iter(|| is_url_bad(black_box("wingwahlau.com")))
    });
    c.bench_function("is_url_bad (miss)", |b| {
        b.iter(|| is_url_bad(black_box("goodwebsite.com")))
    });
}

fn bench_get_host_from_url(c: &mut Criterion) {
    c.bench_function("get_host_from_url", |b| {
        b.iter(|| get_host_from_url(black_box("https://example.com/path/to/page")))
    });
}

// Dynamic overlay read-path cost: the final OR-term every *legit* host now hits.
#[cfg(feature = "dynamic")]
fn bench_dynamic(c: &mut Criterion) {
    use spider_firewall::dynamic;
    // Realistic overlay: 10k discovered-bad hosts.
    let hosts: Vec<String> = (0..10_000).map(|i| format!("evil-{i}.example")).collect();
    dynamic::seed_dynamic_hosts(hosts);
    dynamic::flush();

    // Hot "allow" path — legit host, overlay populated: pays the overlay lookup
    // (foldhash) as the last OR-term across the parent walk-up.
    c.bench_function("is_url_bad (miss, overlay 10k)", |b| {
        b.iter(|| is_url_bad(black_box("a.b.legit-good.example")))
    });
    // Overlay hit (dynamically-discovered host).
    c.bench_function("is_url_bad (dynamic hit)", |b| {
        b.iter(|| is_url_bad(black_box("evil-5000.example")))
    });
    // Non-blocking intake throughput (merges amortized across batches).
    c.bench_function("report_bad (intake)", |b| {
        b.iter(|| dynamic::report_bad(black_box("throughput.example")))
    });
}

#[cfg(not(feature = "dynamic"))]
criterion_group!(
    benches,
    bench_is_bad_website_url,
    bench_is_ad_website_url,
    bench_is_url_bad,
    bench_get_host_from_url,
);
#[cfg(feature = "dynamic")]
criterion_group!(
    benches,
    bench_is_bad_website_url,
    bench_is_ad_website_url,
    bench_is_url_bad,
    bench_get_host_from_url,
    bench_dynamic,
);
criterion_main!(benches);
