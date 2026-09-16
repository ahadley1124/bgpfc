# Hyperframes Composition Brief: OpenBGPify

## Objective
Create a short launch-style brag video for OpenBGPify, a BGP-4 speaker written from scratch
in Rust.

## Output
- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 24.2 seconds

## Source Material
- Project root: `/home/user/bgpfc`
- Primary files read: `README.md`, `RESOURCES.md`, `Cargo.toml`, `src/main.rs`,
  `src/structs.rs`, `src/connection.rs`, `src/setup/json.rs`, `src/impliments/*.rs`
- Product name: OpenBGPify (crate `openbgpify`)
- Tagline / strongest claim: the README's compliance section, which states plainly that the
  project is not compliant with any RFCs and that the authors are working on it
- Key UI or visual moment to recreate: there is no UI. The two real surfaces are the terminal
  (`println!` output in `src/main.rs`) and the 19-byte BGP header as raw bytes (the
  `test_open_message` fixture in `src/main.rs`).
- Copy that must appear verbatim:
  - `cargo run --release -- config.json` (from the README's Run section)
  - `Listening on 0.0.0.0:179`, `Accepted connection from …`, `Sent open message`,
    `Sent keepalive message` (the program's own stdout)
  - `ff` × 16, `00 1d`, `01` (the OPEN-message header bytes from the test fixture)
  - "This project is not compliant with any RFCs." (README, Compliance)

## Creative Direction
- Tone preset: `deadpan`
- Creative direction: a routing daemon that tells the truth about itself
- Interpretation: 5 scenes with long holds, one thought per screen, large sparse type, a lot of
  empty space, very slow crossfades (0.6-0.8s). Nothing accelerates and nothing winks.
- Angle: the README is sincerer and funnier than any joke, so the video reports rather than
  sells. The contrast is between the weight of the material — the protocol the internet's
  routing table runs on, parsed by hand out of raw bytes — and the flatness of the claim.
- Hook: "BGP routes the entire internet." → "We wrote our own."
- Outro / punchline: the compliance sentence, held too long, then the name.
- Avoid:
  - Generic SaaS language
  - Abstract filler visuals (no network-globe graphics, no glowing node meshes)
  - Any visual or audio flourish that editorialises the compliance line

## Visual Identity
- Background: `#0d1117`
- Panel: `#010409` (terminal body), `#161b22` (hex cells)
- Text: `#e6edf3`; muted `#8b949e`
- Accent: `#f74c00` (Rust orange — the language the whole project is written in)
- Display font: `ui-sans-serif, system-ui, sans-serif`
- Code font: `ui-monospace, monospace` — the project's only real typeface is a terminal
- Visual references from the project: terminal stdout; the 19-byte header byte layout

## Storyboard
Use the storyboard in `brag-output/brag-plan.md` as the creative contract.

Scene summary:
1. Hook — 4.39s — "BGP routes the entire internet." / "We wrote our own."
2. The daemon — 5.98s — terminal, five real stdout lines on every other beat
3. The bytes — 6.01s — the 19-byte BGP header in hex, labelled in place
4. Compliance — 4.90s — the README sentence, held
5. Outro — 2.92s — OpenBGPify / "A BGP-4 speaker in Rust."

## Audio
- Audio role: one quiet music bed plus four dry cues, nothing more
- Audio arc: the bed sits low the whole way and drains to silence under the final card
- Music: `assets/music/happy-beats-business-moves-vol-12-by-ende-dot-app.mp3`
- Music treatment: held at 0.15 by the timeline, tweened to 0 across the last ~1.5s
- Music cue guidance: bundled preset at
  `skills/brag/assets/music/cues/happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.md`
  (109.96 BPM). Strong-cue locks: 10.93s (hex reveal), 13.11s (byte labels), 18.56s (compliance
  line), 22.93s (final settle). Beat grid: terminal lines at 4.91 / 6.00 / 7.09 / 8.19 / 9.29 —
  every OTHER beat, because consecutive beats are ~0.55s apart and these lines must be read.
- Audio-reactive treatment: subtle — bass drives a low rust glow behind the terminal and hex
  row (0.1-0.35 opacity, a few percent of scale). No bars, no spectrum, no strobing.
- Audio-coupled moments:
  - Scene 2 command line — soft arrival
  - Scene 3 hex reveal — the one real accent, beat-locked
  - Scene 4 compliance line — a quiet acknowledgement, not a sting
  - Scene 5 wordmark — warm logo cue
- SFX selection guidance: warm, low high-frequency-risk files only, all quiet. No typing ticks
  per character, no success chime on the peering session.
- SFX analysis guidance: `skills/brag/assets/sfx/sfx-analysis.md`
- Exact SFX choice: Hyperframes chooses filenames, timestamps and volume against the animation.
- Audio files: copy the chosen music and SFX into `brag-output/composition/assets/`

## Hyperframes Instructions
Load `hyperframes-core`, `hyperframes-animation`, `hyperframes-creative`, `hyperframes-keyframes`
and `hyperframes-cli`. This is the `/brag` workflow — do not enter the `hyperframes` entry-point
intent interview or its generic promo / launch-video workflow.

Requirements:
- Show real copy and real bytes from the source project.
- Keep all text readable; deadpan holds are long by design, never short.
- Keep the video within 15-25 seconds.
- Include the planned music/SFX layer at deadpan levels (music 0.12-0.18).
- Treat cue metadata as optional timing hints; readability wins over the grid.
- Use 4 strong-cue locks (10.93s, 13.11s, 18.56s, 22.93s); place sequential text on every
  other beat.
- Vendor GSAP locally — the render environment cannot reach the CDN.
- Run `hyperframes check` before render — it is brag's single gate.
