// Does anything in the algebra scene overlap anything else?
// Approximate but honest metrics: monospace advance ~0.60em, serif ~0.50em, cap height ~0.72em.
const fs = require('fs'), vm = require('vm');
const code = fs.readFileSync(process.argv[2], 'utf8').match(/<script>([\s\S]*)<\/script>/)[1];
const AT = Number(process.argv[3]);

let font = '10px mono', align = 'left', texts = [], circles = [], rects = [], depth = 0;
// The px size, NOT the first number in the string. A font with a weight reads
// `300 84px "Newsreader"...`, and parseFloat took the 300 — measuring the wordmark as
// three hundred point and its box as 2100px wide. Conservative, so it never hid a real
// overlap, but it meant the largest text in the film was never actually checked.
const sizeOf = f => { const m = /(\d+(?:\.\d+)?)px/.exec(f); return m ? parseFloat(m[1]) : 10; };
const isMono = f => /mono|Menlo|Consolas|SF Mono/i.test(f);
const advance = (s, f) => s.length * sizeOf(f) * (isMono(f) ? 0.60 : 0.50);

const ctx = new Proxy({}, {
  get(_, k) {
    if (k === 'save') return () => depth++;
    if (k === 'restore') return () => depth--;
    if (k === 'measureText') return s => ({ width: advance(s, font) });
    if (k === 'fillText') return (s, x, y) => texts.push({ s, x, y, size: sizeOf(font), align, font });
    if (k === 'arc') return (x, y, r) => circles.push({ x, y, r });
    // `box()` draws through rect/roundRect. fillRect and strokeRect (the veil and the frame
    // line) are deliberately NOT recorded — they are full-bleed and every text crosses them.
    if (k === 'rect' || k === 'roundRect')
      return (x, y, w, h) => rects.push({ x0: x, y0: y, x1: x + w, y1: y + h });
    if (k === 'font') return font;
    if (k === 'textAlign') return align;
    if (k === 'letterSpacing') return '0px';
    if (k === 'canvas') return { width: 1600, height: 900 };
    return () => {};
  },
  set(_, k, v) { if (k === 'font') font = v; if (k === 'textAlign') align = v; return true; },
  has() { return true; },
});

const el = () => ({ style: {}, getContext: () => ctx, addEventListener() {}, setAttribute() {},
  appendChild() {}, setPointerCapture() {}, releasePointerCapture() {},
  getBoundingClientRect: () => ({ width: 1180, height: 663, left: 0, top: 0 }), width: 0, height: 0 });
let raf = null;
const sb = { document: { getElementById: el, createElement: el, addEventListener() {},
                         fonts: { ready: Promise.resolve() }, body: {} },
  window: { devicePixelRatio: 2, matchMedia: () => ({ matches: false }), addEventListener() {},
            requestAnimationFrame: cb => { raf = cb; } },
  requestAnimationFrame: cb => { raf = cb; }, performance: { now: () => 0 },
  setTimeout: () => 0, console, Math, Number, String, Array, Object, Promise, Date, JSON };
sb.globalThis = sb;
vm.createContext(sb); vm.runInContext(code, sb, { timeout: 15000 });

(async () => {
  await new Promise(r => setImmediate(r));
  let now = 0;
  sb.performance.now = () => now;
  for (let i = 0; i <= Math.round(AT * 60); i++) {
    now = (i / 60) * 1000;
    if (i === Math.round(AT * 60)) { texts = []; circles = []; rects = []; }
    const cb = raf; raf = null; if (!cb) break; cb(now);
  }

  const box = t => {
    const w = advance(t.s, t.font);
    const x = t.align === 'center' ? t.x - w / 2 : t.align === 'right' ? t.x - w : t.x;
    return { ...t, x0: x, x1: x + w, y0: t.y - t.size * 0.72, y1: t.y + t.size * 0.22 };
  };
  const boxes = texts.filter(t => t.s.trim()).map(box);
  const hit = (a, b) => a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;

  console.log(`t = ${AT}s   ${boxes.length} text items, ${circles.length} circles, ${rects.length} boxes\n`);
  const bad = [];
  for (let i = 0; i < boxes.length; i++)
    for (let j = i + 1; j < boxes.length; j++)
      if (hit(boxes[i], boxes[j])) bad.push(`TEXT/TEXT  "${boxes[i].s}"  ×  "${boxes[j].s}"`);

  // Text sitting on top of a ring outline is the reported defect.
  // The Venn rings only. The revocation pulse is also a large circle, but it is a moving sweep
  // that is MEANT to cross the enforcement boxes. It was excluded by its exact origin, which
  // broke silently the moment that node moved twenty-four pixels — every frame of the revoke
  // scene then reported a false overlap. The rings live in the middle of the frame and the
  // pulse starts near the top, so the band is the stable discriminator, not the coordinate.
  const rings = circles.filter(c => c.r > 90 && c.y > 220);
  for (const b of boxes)
    for (const c of rings) {
      const cxp = Math.max(b.x0, Math.min(c.x, b.x1));
      const cyp = Math.max(b.y0, Math.min(c.y, b.y1));
      if (Math.hypot(c.x - cxp, c.y - cyp) < c.r)
        bad.push(`TEXT/RING  "${b.s}" inside ring at (${c.x.toFixed(0)},${c.y.toFixed(0)}) r=${c.r}`);
    }

  // Text that CROSSES a box outline. Fully inside is the normal case — a label in its own
  // box — and fully outside is fine; it is the partial overlap that is always a mistake.
  // This check did not exist, which is how a question ran through the `hr-records` box.
  for (const b of boxes)
    for (const r of rects) {
      const hits = b.x0 < r.x1 && r.x0 < b.x1 && b.y0 < r.y1 && r.y0 < b.y1;
      const inside = b.x0 >= r.x0 - 2 && b.x1 <= r.x1 + 2 && b.y0 >= r.y0 - 2 && b.y1 <= r.y1 + 2;
      if (hits && !inside)
        bad.push(`TEXT/BOX   "${b.s}" crosses the edge of a box at ` +
                 `(${r.x0.toFixed(0)},${r.y0.toFixed(0)})-(${r.x1.toFixed(0)},${r.y1.toFixed(0)})`);
    }

  boxes.sort((a, b) => a.y0 - b.y0).forEach(b =>
    console.log(`  y ${b.y0.toFixed(0).padStart(4)}–${b.y1.toFixed(0).padStart(4)}   x ${b.x0.toFixed(0).padStart(5)}–${b.x1.toFixed(0).padStart(5)}   ${b.s}`));

  console.log('');
  console.log(bad.length ? 'OVERLAPS:\n  ' + [...new Set(bad)].join('\n  ') : 'no overlaps');
  process.exit(bad.length ? 1 : 0);
})();
