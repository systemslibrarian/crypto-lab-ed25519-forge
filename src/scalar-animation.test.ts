import { expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { scalarMultPath } from './forge';

const seed = Uint8Array.from('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'.match(/../g)!, b => parseInt(b, 16));
const publicHex = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
// Independently hash and prune the seed per RFC 8032 §5.1.5; do not obtain the
// expected bit sequence from the same noble helper used by the animation.
async function clampedScalar(input: Uint8Array): Promise<bigint> {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-512', new Uint8Array(input))).subarray(0, 32);
  bytes[0] &= 248;
  bytes[31] = (bytes[31] & 127) | 64;
  return Array.from(bytes).reduceRight((n, b) => (n << 8n) | BigInt(b), 0n);
}
const hex = (point: typeof ed25519.Point.BASE) => Array.from(point.toBytes(), b => b.toString(16).padStart(2, '0')).join('');

it('RFC TEST2 begins with the clamped prefix, not reduced-scalar bits', () => {
  expect(scalarMultPath(seed).slice(0, 4).map(s => s.op)).toEqual(['start', 'double', 'double', 'add']);
});

it('every non-summary frame is exactly its labelled group operation', async () => {
  for (const bits of [0, 12, 254]) {
    const scalar = await clampedScalar(seed);
    let point = ed25519.Point.BASE;
    const expected = [{ op: 'start', point: hex(point) }];
    for (let bit = 253; bit >= 254 - bits; bit--) {
      point = point.double();
      expected.push({ op: 'double', point: hex(point) });
      if ((scalar >> BigInt(bit)) & 1n) {
        point = point.add(ed25519.Point.BASE);
        expected.push({ op: 'add', point: hex(point) });
      }
    }
    const real = scalarMultPath(seed, bits).filter(s => s.op !== 'summary');
    expect(real.map(s => ({ op: s.op, point: s.pointHex }))).toEqual(expected);
    for (let i = 0; i < real.length; i++) expect(real[i].index).toBe(i);
  }
});

it('a truncated endpoint is a summary, with omitted operations separately counted', async () => {
  const path = scalarMultPath(seed);
  const last = path.at(-1)!;
  expect(last.op).toBe('summary');
  expect(last.index).toBe(path.at(-2)!.index);
  expect(last.skippedBits).toBe(242);
  const scalar = await clampedScalar(seed);
  let remaining = 0;
  for (let bit = 241; bit >= 0; bit--) remaining += 1 + Number((scalar >> BigInt(bit)) & 1n);
  expect(last.remainingOperations).toBe(remaining);
  expect(last.pointHex).toBe(publicHex);
  expect(last.isFinal).toBe(true);
});

it('a full clamped walk reaches the RFC key without an endpoint jump', () => {
  const path = scalarMultPath(seed, 254);
  expect(path.some(s => s.op === 'summary')).toBe(false);
  expect(path.at(-1)!.op).toBe('double'); // pruning clears the lowest three bits
  expect(path.at(-1)!.pointHex).toBe(publicHex);
  expect(path.at(-1)!.isFinal).toBe(true);
  expect(path.filter(s => s.isFinal)).toHaveLength(1);
});

it('a zero-bit prefix reports zero displayed operations and a separate summary', () => {
  const path = scalarMultPath(seed, 0);
  expect(path.map(s => s.op)).toEqual(['start', 'summary']);
  expect(path.at(-1)!.index).toBe(0);
  expect(path.at(-1)!.skippedBits).toBe(254);
  expect(path.at(-1)!.pointHex).toBe(publicHex);
});

it('invalid prefix lengths fail explicitly', () => {
  for (const bits of [-1, 255, 1.5, NaN]) expect(() => scalarMultPath(seed, bits)).toThrow(RangeError);
});
