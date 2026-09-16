# Brag Plan: OpenBGPify

## What is this app?
A BGP-4 speaker written from scratch in Rust — it binds TCP/179, hand-parses the 19-byte BGP
message header, and codes OPEN, UPDATE, KEEPALIVE and NOTIFICATION messages byte for byte,
in about 700 lines with two dependencies. Its README states, with no hedging, that it is
compliant with zero RFCs.

## The angle
The README is funnier than any joke a video could add, because it is completely sincere:
"This project is not compliant with any RFCs." So the video does not sell the project — it
reports it. The brag is the contrast between the seriousness of the material (the protocol
that holds the internet's routing table together, parsed by hand out of raw bytes) and the
flatness of the claim. Play it absolutely straight and the audience does the laughing.

## Hook (first 2-3 seconds)
"BGP routes the entire internet." — stated as a fact, held. Then, same size, same weight,
no escalation: "We wrote our own."

## Key moments (the middle)
- The daemon actually running: a terminal with the real `cargo run` invocation and the real
  `println!` output from `src/main.rs` — Listening on 0.0.0.0:179, Accepted connection from…,
  Sent open message, Sent keepalive message.
- The 19-byte BGP header as hex cells, taken verbatim from the `test_open_message` fixture in
  `src/main.rs`: sixteen `ff` marker bytes, the `00 1d` length, the `01` type. Labelled in place.
  This is the "show the thing" scene — the thing is bytes.
- The flat technical fact underneath it: parsed by hand, two dependencies.

## Outro / punchline
The README's compliance section, verbatim, held longer than is comfortable. Then the name,
and one line that describes exactly what it is with no adjectives.

## User flow worth showing
This is a daemon, not an app — there is no UI, so the "flow" is the peering session, from
`src/main.rs`:
1. Entry — `cargo run --release -- config.json`; the listener binds 0.0.0.0:179.
2. Key action — a peer connects; `init_peer` writes an OPEN message, then a KEEPALIVE.
3. Result — the bytes on the wire: the 19-byte header the code builds and round-trips in its
   own tests.
The terminal scene is beat 1 and 2; the hex scene is beat 3.

## Tone
- Preset: `deadpan`
- Creative direction: a routing daemon that tells the truth about itself
- Interpretation: long holds, one thought per screen, large sparse type and a lot of empty
  space. Very slow crossfades. Nothing accelerates, nothing winks, nothing is emphasised.
  The pace is the joke.

## Format: landscape — 1920x1080
## Duration: 24.2 seconds

## Visual identity (from the project)
The project has no stylesheet — it is a Rust binary — so the identity comes from the two
surfaces it actually has: a terminal and raw bytes.
- Background: `#0d1117` (terminal dark)
- Panel: `#010409` terminal body, `#161b22` hex cells
- Accent: `#f74c00` (Rust orange — the language the whole thing is written in)
- Text: `#e6edf3`; muted `#8b949e`
- Display font: `ui-sans-serif, system-ui, sans-serif`
- Body/code font: `ui-monospace, monospace` — the project's only real typeface is a terminal
- Strongest visual element: the sixteen `ff` bytes of the BGP marker, laid out as a row of
  hex cells. It is unmistakably this project and it is genuinely the first thing on the wire.

## Share copy (draft)
I wrote a BGP-4 speaker in Rust. It binds 179, hand-parses the 19-byte header, and codes
OPEN/UPDATE/KEEPALIVE/NOTIFICATION in ~700 lines with two dependencies. It is compliant with
zero RFCs. We are working on it.

## Audio direction
- Role: one quiet music bed plus a very small number of dry cues
- Music: `happy-beats-business-moves-vol-12-by-ende-dot-app.mp3` (109.96 BPM, "steady and clean")
- Music treatment: from 0 at 0.15 — deliberately low, present but never driving — fading to 0
  across the last ~1.5s so the final card sits in silence
- Music cue guidance: preset read from `assets/music/cues/…vol-12….music-cues.md`.
  Strong cues targeted: **10.93s** (the hex header reveal), **13.11s** (the byte labels),
  **18.56s** (the compliance line), **22.93s** (the final settle). Beat-grid windows for the
  terminal lines: 4.91 / 6.00 / 7.09 / 8.19 / 9.29 — every beat is ~0.55s apart at this tempo,
  so the lines are placed on **every other** beat (~1.1s) to clear the reading floor.
- Audio-reactive treatment: subtle. Bass drives a low rust-coloured glow behind the terminal
  and the hex row — 0.1 to 0.35 opacity and a few percent of scale. Nothing else moves with it.
  No bars, no spectrum, no pulsing.
- SFX posture: very sparse — four cues in the whole video, all warm and low-risk, all quiet.
- Audio-coupled moments: the command line appearing, the hex header reveal, the compliance
  line, the final wordmark.
- Restraint rule: no typing sounds per character, no success chime on the peering session, and
  absolutely nothing triumphant on the compliance line. The sound must not editorialise.

## Storyboard

### Scene 1 — Hook — 4.39s (0 → 4.39)
Near-black frame, a lot of empty space. "BGP routes the entire internet." fades up at 0.56s.
"We wrote our own." fades up at 2.19s, same size, same weight, in rust orange. Both hold.
Sequential/interaction: two lines, 1.63s apart — far past the reading floor, deliberately slow.
Audio intent: the bed is already running, very low. Nothing marks either line.
Audio-coupled idea: none.
Music: quiet, steady.
Transition mood: slow crossfade → Scene 2

### Scene 2 — The daemon — 5.98s (4.39 → 10.37)
A terminal panel, centred, generous margins. Real output from `src/main.rs`, one line at a time
on every other beat: the `cargo run` command at 4.91s, "Listening on 0.0.0.0:179" at 6.00s,
"Accepted connection from 10.0.1.136:54122" at 7.09s, "Sent open message" at 8.19s, "Sent
keepalive message" at 9.29s. A cursor block rests after the last line.
Sequential/interaction: yes — five terminal lines, each on every other beat (~1.1s apart), each
held; the session is the interaction.
Audio intent: one soft cue as the command lands, then nothing. The peering session is not an
achievement, it is just what the program does.
Audio-coupled idea: single soft drop on the command line.
Music: unchanged.
Transition mood: slow crossfade → Scene 3

### Scene 3 — The bytes — 6.01s (10.37 → 16.38)
Beat-locked to the 10.93s strong cue: the 19-byte BGP header appears as a row of hex cells,
verbatim from the `test_open_message` fixture — sixteen `ff` bytes in rust orange, then `00 1d`,
then `01`. At 13.11s (strong cue) three labels appear beneath their byte groups at once:
"marker · 16 bytes", "length", "type". At 14.73s, one flat line: "Parsed by hand. Two dependencies."
Sequential/interaction: yes — the hex row lands as one block, the three labels arrive together
rather than one per beat, because three separate 0.55s reveals would outrun reading.
Audio intent: one dry, warm cue on the hex reveal. Nothing on the labels.
Audio-coupled idea: single reveal cue at 10.93s.
Music: unchanged.
Transition mood: long hold, then slow crossfade → Scene 4

### Scene 4 — Compliance — 4.90s (16.38 → 21.28)
Empty frame. A small muted label, "Compliance", at 16.93s. Then at 18.56s (strong cue), the
README's own sentence at full size: "This project is not compliant with any RFCs." It holds for
nearly three seconds — longer than is comfortable, which is the entire joke. At 19.66s, smaller
and lower: "We are working on it."
Sequential/interaction: none. One sentence, held.
Audio intent: one quiet bell as the sentence lands. Not a sting — an acknowledgement.
Audio-coupled idea: single soft accent at 18.56s.
Music: unchanged, beginning to thin.
Transition mood: slow crossfade → Scene 5

### Scene 5 — Outro — 2.92s (21.28 → 24.20)
"OpenBGPify" at 21.38s. A rust rule draws under it at 21.84s. "A BGP-4 speaker in Rust." at
22.37s. A final, almost invisible settle on the 22.93s strong cue. The music fades out from
under all of it.
Sequential/interaction: none — one held frame.
Audio intent: one warm cue on the name, then the bed drains away and the last second is quiet.
Audio-coupled idea: logo cue at 21.38s.
Music: fades to zero across the last ~1.5s.
Transition mood: hold to end.

**Music mood for this video:** deadpan
**Audio summary:** A deliberately quiet bed runs underneath at a level you have to look for,
punctuated by exactly four warm, low cues — the command, the bytes, the compliance line and the
name — before draining to silence under the final card.
