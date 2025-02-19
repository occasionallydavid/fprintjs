# fprintjs

Interview homework using YARA to match patterns against known interesting JS
sample files, and a smoke test for detecting false positives in new patterns
against a large set of previously known scripts.



# Requirements

* Rust 1.84, maybe earlier
* Debian, or at least local OS equivalent of "libyara-dev" installed



# Build

`cargo build --release`


# Test own samples

`target/release/fprintjs test-own-samples`


# Smoke test

`target/release/fprintjs smoke-test`



# TODO

- [ ] Larger collection of legitimate JS samples to test against
- [ ] Parallelize smoke test

