# Fuzz targets

cargo-fuzz targets for every decoder in `bgpfc-wire` and for the
configuration parser (AGENTS.md §5). This
crate is deliberately outside the workspace: `libfuzzer-sys` and
`arbitrary` are allowed here and nowhere else (AGENTS.md §1.2).

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run update -- -max_total_time=600
```

Each target also asserts a round trip for inputs the decoder accepts, so
a crash means either a panic in the decoder or an encode/decode asymmetry.
Crashing inputs land in `fuzz/artifacts/<target>/`; reproduce with
`cargo +nightly fuzz run <target> artifacts/<target>/<file>` and turn the
input into a unit test before fixing.

CI runs each target briefly on every push; long campaigns are run by hand.
