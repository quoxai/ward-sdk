import { describe, it, expect } from 'vitest';
import { parseStrictJson } from '../src/strict-json.js';

/**
 * SPEC §3.2 rule 5: "A parser feeding canonicalization or verification MUST
 * reject JSON objects containing duplicate member names." Node's built-in
 * `JSON.parse` silently does last-wins on duplicates, so this SDK ships its
 * own minimal strict parser for the two places untrusted bytes are read:
 * FileStore (NDJSON lines) and the ward-verify CLI (chain export files).
 */
describe('parseStrictJson — SPEC §3.2 rule 5', () => {
  it('parses ordinary JSON identically to JSON.parse', () => {
    const text = '{"a":1,"b":[1,2,3],"c":{"d":"e"},"f":true,"g":null,"h":-1.5}';
    expect(parseStrictJson(text)).toEqual(JSON.parse(text));
  });

  it('rejects an object with a duplicate top-level member name', () => {
    expect(() => parseStrictJson('{"a":1,"a":2}')).toThrow(/duplicate/i);
  });

  it('rejects a duplicate member name in a nested object', () => {
    expect(() => parseStrictJson('{"a":{"x":1,"x":2}}')).toThrow(/duplicate/i);
  });

  it('rejects a duplicate member name inside an array of objects', () => {
    expect(() => parseStrictJson('[{"x":1,"x":2}]')).toThrow(/duplicate/i);
  });

  it('accepts the same key repeated in two different sibling objects', () => {
    expect(parseStrictJson('[{"x":1},{"x":2}]')).toEqual([{ x: 1 }, { x: 2 }]);
  });

  it('handles escaped strings, unicode escapes, and nested structures', () => {
    const text = String.raw`{"s":"a\"b\\c\né","arr":[1,-2,3.5,1e2]}`;
    expect(parseStrictJson(text)).toEqual(JSON.parse(text));
  });

  it('throws on malformed JSON (not silently returning undefined)', () => {
    expect(() => parseStrictJson('{"a":}')).toThrow();
    expect(() => parseStrictJson('not json')).toThrow();
    expect(() => parseStrictJson('{"a":1}extra')).toThrow();
  });
});
