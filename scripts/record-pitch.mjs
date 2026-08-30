#!/usr/bin/env node
// Record docs/pitch.html to a frame sequence, then to video.
//
//     node scripts/record-pitch.mjs [--fps 30] [--out build/pitch]
//
// ## Why this works at all, and why there is no video library here
//
// The film renders as a pure function of `t` — that property was put in so scrubbing and
// chapter jumps would be free, and it pays for itself again here: a frame can be demanded
// rather than waited for. So recording is a loop that says "draw t, screenshot, next", and the
// output is exact rather than a capture of whatever the machine managed in real time. A dropped
// frame is impossible; a slow machine makes the RECORDING slower, never the film.
//
// It drives the Chrome already installed on the machine over the DevTools protocol, which is
// HTTP for discovery and a WebSocket for commands — both built into Node 22. Puppeteer would
// add a dependency and a second Chromium download to do the same forty lines.
//
// ## What it does NOT do
//
// It does not verify that the frames look right. `scripts/.pitch-layout-check.js` does that,
// against the same source, and is the thing to run first.

import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";

const arg = (name, dflt) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : dflt;
};
const FPS = Number(arg("fps", 30));
// Supersample. The film draws its canvas backing store at `devicePixelRatio` capped to 2, so
// recording at deviceScaleFactor 1 rasterised every glyph at 1x and the result was visibly
// softer than the same page on any Retina screen — which renders at 2x and downsamples. This
// captures at 2x and ffmpeg does the downsample, which is what the browser was doing all along.
const SCALE = Number(arg("scale", 2));
const OUT = path.resolve(arg("out", "build/pitch"));
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const W = 1920, H = 1080, PORT = 8731, CDP = 9333;
// PNG, not JPEG. The capture is now one stage of two lossy steps rather than one, and the
// design puts thin cyan, amber and green text on near-black — exactly what 4:2:0 chroma
// subsampling smears. H.264 subsamples at the end regardless; doing it twice is a choice.
const SHOT = { format: "png" };

/** The page, with a recording hook and the player chrome hidden. */
async function preparePage(dir) {
  let html = await readFile(path.join(ROOT, "docs/pitch.html"), "utf8");

  // A handle on the film's own clock. `render`, `resize`, `playing` and `clock` are all in
  // scope at the end of the IIFE, so nothing in the film has to be restructured to be recorded.
  const hook = `
  window.__wc = {
    dur: DUR,
    prepare() { playing = false; resize(); },
    frame(t) { clock = cl(t, 0, DUR); render(clock); },
  };
`;
  const close = "})();\n</script>";
  if (!html.includes(close)) throw new Error("could not find the end of the film's IIFE");
  html = html.replace(close, hook + close);

  // The frame only. The transport and the legend belong to the web page, not to the film.
  html = html.replace("</style>", `</style>
<style>
  html, body { margin: 0; padding: 0; background: #0B0F17; overflow: hidden; }
  .reel { width: 100vw; gap: 0; }
  .transport, .legend { display: none !important; }
  .frame { border: 0; border-radius: 0; }
</style>`);

  await writeFile(path.join(dir, "rec.html"), html);
}

/** Minimal static server. The film loads a webfont, so file:// would fight the CSP for nothing. */
function serve(dir) {
  const types = { ".html": "text/html; charset=utf-8" };
  const srv = createServer(async (req, res) => {
    const name = req.url.split("?")[0] === "/" ? "/rec.html" : req.url.split("?")[0];
    try {
      const body = await readFile(path.join(dir, name));
      res.writeHead(200, { "content-type": types[path.extname(name)] || "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404).end("no");
    }
  });
  return new Promise(r => srv.listen(PORT, "127.0.0.1", () => r(srv)));
}

/** One CDP connection, with promise-per-command-id. */
async function connect() {
  let targets, lastErr;
  for (let i = 0; i < 60; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${CDP}/json/list`)).json(); break; }
    catch (e) { lastErr = e; await new Promise(r => setTimeout(r, 250)); }
  }
  if (!targets) throw new Error(`Chrome never opened a debugging port: ${lastErr}`);
  const page = targets.find(t => t.type === "page");
  if (!page) throw new Error("Chrome exposed no page target");

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((ok, bad) => { ws.onopen = ok; ws.onerror = () => bad(new Error("CDP socket refused")); });

  let id = 0;
  const waiting = new Map(), events = new Map();
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.id && waiting.has(m.id)) {
      const { ok, bad } = waiting.get(m.id); waiting.delete(m.id);
      m.error ? bad(new Error(`${m.error.message}`)) : ok(m.result);
    } else if (m.method && events.has(m.method)) {
      events.get(m.method)(); events.delete(m.method);
    }
  };
  return {
    send: (method, params = {}) => new Promise((ok, bad) => {
      waiting.set(++id, { ok, bad });
      ws.send(JSON.stringify({ id, method, params }));
    }),
    once: method => new Promise(ok => events.set(method, ok)),
    close: () => ws.close(),
  };
}

const main = async () => {
  const frames = path.join(OUT, "frames");
  await rm(frames, { recursive: true, force: true });
  await mkdir(frames, { recursive: true });
  const tmp = path.join(OUT, "page");
  await mkdir(tmp, { recursive: true });
  await preparePage(tmp);
  const srv = await serve(tmp);

  const profile = path.join(OUT, "chrome-profile");
  const chrome = spawn(CHROME, [
    "--headless=new", `--remote-debugging-port=${CDP}`, `--user-data-dir=${profile}`,
    "--no-first-run", "--no-default-browser-check", "--disable-extensions",
    "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
    `--window-size=${W},${H}`, `http://127.0.0.1:${PORT}/rec.html`,
  ], { stdio: "ignore" });

  const cdp = await connect();
  await cdp.send("Page.enable");
  await cdp.send("Emulation.setDeviceMetricsOverride",
    { width: W, height: H, deviceScaleFactor: SCALE, mobile: false });

  // The display face has to be present before the first frame, or the opening seconds record
  // in the fallback and then jump when Newsreader arrives.
  await cdp.send("Runtime.evaluate", { expression: "document.fonts.ready", awaitPromise: true });
  const dur = (await cdp.send("Runtime.evaluate",
    { expression: "window.__wc.prepare(), window.__wc.dur", returnByValue: true })).result.value;
  if (typeof dur !== "number") throw new Error("the recording hook did not install");

  const total = Math.round(dur * FPS);
  process.stdout.write(`recording ${dur}s at ${FPS}fps = ${total} frames, ` +
    `${W * SCALE}x${H * SCALE} (${SCALE}x, downsampled to ${W}x${H} at encode)\n`);

  for (let i = 0; i < total; i++) {
    const t = i / FPS;
    await cdp.send("Runtime.evaluate", { expression: `window.__wc.frame(${t})` });
    const shot = await cdp.send("Page.captureScreenshot", SHOT);
    await writeFile(path.join(frames, `f${String(i).padStart(6, "0")}.png`),
                    Buffer.from(shot.data, "base64"));
    if (i % 300 === 0 || i === total - 1) {
      process.stdout.write(`  ${i + 1}/${total}  t=${t.toFixed(1)}s\n`);
    }
  }

  cdp.close();
  chrome.kill();
  srv.close();
  process.stdout.write(`frames in ${frames}\n`);
};

main().catch(e => { console.error("FAILED:", e.message); process.exit(1); });
