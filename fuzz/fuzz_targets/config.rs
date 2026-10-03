//! Any text parses to a configuration or an error report; never a panic
//! (AGENTS.md §1.6, §5 `bgpfc-config` row).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        match bgpfc_config::parse_str("fuzz", text) {
            Ok(cfg) => {
                // The diff against itself is empty, and rendering works.
                assert!(bgpfc_config::ConfigDiff::between(&cfg, &cfg).is_empty());
                let _ = format!("{cfg:?}");
            }
            Err(e) => {
                let _ = e.to_string();
            }
        }
    }
});
