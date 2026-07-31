# Demo video build

`assets/security-review-demo-en.mp4` is built from the HTML scenes in `scenes/`.

Every number, node name, finding ID and check name in the scenes is copied from
committed repository output:

| Scene | Source of the shown content |
| --- | --- |
| scene-02 | `workflows/unsafe-support-agent.json` |
| scene-03 | `reports/unsafe-support-agent-audit.md` |
| scene-04, scene-05 | `reports/unsafe-support-agent-exposure.svg` |
| scene-06 | `reports/hardened-support-agent-audit.md` |
| scene-07 | `reports/runtime-gate-demo.md` and the staging fixture node list |

## Rebuild

Requirements: a Chromium or Chrome binary and ffmpeg with libx264.

```bash
CHROME=/path/to/chrome bash media/demo/build.sh
```

The script renders each scene to a 1920x1080 PNG and encodes a 30 fps H.264
MP4 with the per-scene durations in `timing.txt` (64 seconds total). There is
no audio track, no animation and no external network access.

If a scene needs a copy change, edit the HTML file and run the build again.
Do not change a number without changing the report it comes from.
