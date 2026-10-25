// Draws the Human ID mark (a face inside scan brackets) as SVG and as PNGs, with no image libraries.
import { writeFileSync } from 'node:fs';
import { deflateSync, crc32 } from 'node:zlib';

const GREEN = [0x17, 0x79, 0x4a];
const STROKE = 6;
const polylines = [
  [[24, 38], [24, 24], [38, 24]],
  [[62, 24], [76, 24], [76, 38]],
  [[24, 62], [24, 76], [38, 76]],
  [[62, 76], [76, 76], [76, 62]],
  [[41, 42], [41, 48]],
  [[59, 42], [59, 48]],
];
// The smile is a quadratic curve, flattened into short segments for the PNG.
const smile = [];
for (let i = 0; i <= 24; i++) {
  const t = i / 24;
  smile.push([(1 - t) ** 2 * 39 + 2 * (1 - t) * t * 50 + t ** 2 * 61, (1 - t) ** 2 * 58 + 2 * (1 - t) * t * 68 + t ** 2 * 58]);
}
polylines.push(smile);

const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" rx="22" fill="#17794a"/><g fill="none" stroke="#fff" stroke-width="${STROKE}" stroke-linecap="round" stroke-linejoin="round">${polylines
  .slice(0, 6)
  .map((p) => `<path d="M${p.map((q) => q.join(' ')).join(' L')}"/>`)
  .join('')}<path d="M39 58 Q50 68 61 58"/></g></svg>\n`;
writeFileSync('public/icon.svg', svg);

function distToSegment(px, py, [ax, ay], [bx, by]) {
  const dx = bx - ax;
  const dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

function onStroke(x, y) {
  for (const line of polylines) {
    for (let i = 1; i < line.length; i++) if (distToSegment(x, y, line[i - 1], line[i]) <= STROKE / 2) return true;
  }
  return false;
}

function png(size) {
  const ss = 4;
  const rows = [];
  for (let y = 0; y < size; y++) {
    const row = Buffer.alloc(1 + size * 4);
    for (let x = 0; x < size; x++) {
      let white = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const ux = ((x + (sx + 0.5) / ss) / size) * 100;
          const uy = ((y + (sy + 0.5) / ss) / size) * 100;
          if (onStroke(ux, uy)) white++;
        }
      }
      const a = white / (ss * ss);
      const o = 1 + x * 4;
      for (let c = 0; c < 3; c++) row[o + c] = Math.round(GREEN[c] * (1 - a) + 255 * a);
      row[o + 3] = 255;
    }
    rows.push(row);
  }
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body) >>> 0);
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(Buffer.concat(rows))),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

for (const size of [180, 192, 512]) writeFileSync(`public/icon-${size}.png`, png(size));
console.log('Wrote public/icon.svg and icon-180/192/512.png');
