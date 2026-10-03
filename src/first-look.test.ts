import { describe, expect, it } from 'vitest';
import { flipOneCharacter } from './first-look';

/**
 * The front-section promises a reader that exactly ONE character changed and
 * that the note still reads the same. These assert that promise, so a change
 * that rewrites more of the note turns a test red rather than quietly making
 * the lesson weaker.
 */
describe('flipOneCharacter', () => {
  it('changes exactly one character and only its case', () => {
    const before = 'Meet me at the library at four.';
    const flip = flipOneCharacter(before);
    expect(flip).not.toBeNull();
    const after = flip!.changed;

    expect(after).not.toBe(before);
    expect(after.length).toBe(before.length);
    expect(after.toLowerCase()).toBe(before.toLowerCase());
    expect([...before].filter((ch, i) => ch !== after[i])).toHaveLength(1);
  });

  it('reports the character it moved', () => {
    const flip = flipOneCharacter('Meet me at four.');
    expect(flip).toEqual({ changed: 'meet me at four.', from: 'M', to: 'm' });
  });

  it('skips leading non-letters and flips the first letter it finds', () => {
    expect(flipOneCharacter('123 go')).toEqual({ changed: '123 Go', from: 'g', to: 'G' });
  });

  it('returns null rather than inventing a change when there is no letter', () => {
    expect(flipOneCharacter('1234 5678 !?')).toBeNull();
    expect(flipOneCharacter('')).toBeNull();
  });
});
