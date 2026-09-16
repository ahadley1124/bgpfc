# brag-output

Produced by the [`/brag`](https://github.com/latent-spaces/brag) skill, which turns a project
into a short launch video via [Hyperframes](https://www.npmjs.com/package/hyperframes).

| File | What it is |
|---|---|
| `brag.mp4` | The rendered video (1920x1080, 30fps, H.264 + AAC). Its first frame is `brag.jpg`, so every player and platform uses that as the idle thumbnail. |
| `brag.jpg` | The poster frame — also the custom-thumbnail upload for platforms that accept one, and the `poster=` image for any `<video>` embed. |
| `brag-plan.md` | The creative plan and beat-by-beat storyboard. |
| `composition-brief.md` | The handoff brief given to Hyperframes. |
| `share-copy.txt` | The caption to post with the video. |
| `composition/` | The Hyperframes project the video was rendered from. |

## Re-rendering

`composition/` is committed without its third-party audio and its vendored copy of GSAP
(see `.gitignore`), so restore those first:

```bash
npm i -g hyperframes
npx hyperframes browser ensure           # Chrome Headless Shell for rendering
sudo apt-get install -y ffmpeg           # required by the renderer

# music + SFX come from the /brag skill's bundled asset library
git clone https://github.com/latent-spaces/brag /tmp/brag
mkdir -p composition/assets/music composition/assets/sfx composition/vendor
cp -r /tmp/brag/skills/brag/assets/music/*.mp3 composition/assets/music/
cp -r /tmp/brag/skills/brag/assets/sfx/{interface,impact,ui} composition/assets/sfx/

# GSAP is vendored rather than loaded from a CDN — the renderer runs offline
npm pack gsap@3.14.2 && tar -xzf gsap-3.14.2.tgz
cp package/dist/gsap.min.js composition/vendor/

cd composition && hyperframes check && hyperframes render --quality delivery --output ../brag.mp4
```

Only the exact tracks and effects named in `composition/index.html` are needed, not the whole
library. The bundled music is "Happy Beats / Business Moves" by [ende.app](https://ende.app/en)
and the sound effects are CC0 from [Kenney](https://kenney.nl/); confirm the music terms cover
your intended use before publishing the video anywhere public.
