//! Any pattern compiles or errors, and matching any path never panics
//! (AGENTS.md §5, `bgpfc-policy` row).
#![no_main]

use bgpfc_policy::AsPathRegex;
use bgpfc_wire::types::Asn;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let at = usize::from(split).min(rest.len());
    let (pattern, path) = rest.split_at(at);
    let Ok(pattern) = std::str::from_utf8(pattern) else {
        return;
    };
    let Ok(re) = AsPathRegex::new(pattern) else {
        return;
    };
    let path: Vec<Asn> = path
        .chunks(2)
        .map(|c| Asn(u32::from(c[0]) * 256 + u32::from(*c.get(1).unwrap_or(&0))))
        .collect();
    let _ = re.is_match(&path);
    let _ = re.to_string();
});
