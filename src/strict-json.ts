/**
 * A minimal, dependency-free strict JSON parser (SPEC §3.2 rule 5).
 *
 * Node's built-in `JSON.parse` silently accepts duplicate object member
 * names with last-wins semantics, which the WARD-CANON-1 profile forbids: a
 * single byte sequence could otherwise carry two different assertions about
 * the same field. This parser is a standard recursive-descent JSON parser
 * with one deliberate deviation — every object literal tracks the member
 * names it has already seen and throws on a repeat, at every nesting level.
 *
 * Use this (not `JSON.parse`) at every boundary where untrusted WARD bytes
 * enter the SDK: FileStore's NDJSON reads and the ward-verify CLI's chain
 * export / anchor file reads. `verifyChain` itself operates on already
 * in-memory JS objects, which cannot represent a duplicate key by
 * construction, so this rule cannot be re-checked there; it must be applied
 * at the parse boundary.
 */
export function parseStrictJson(text: string): unknown {
  let i = 0;
  const n = text.length;

  function fail(message: string): never {
    throw new Error(`parseStrictJson: ${message} at offset ${i}`);
  }

  function skipWs(): void {
    while (i < n) {
      const c = text[i];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') i++;
      else break;
    }
  }

  function parseValue(): unknown {
    skipWs();
    if (i >= n) fail('unexpected end of input');
    const c = text[i];
    if (c === '{') return parseObject();
    if (c === '[') return parseArray();
    if (c === '"') return parseString();
    if (c === '-' || (c >= '0' && c <= '9')) return parseNumber();
    if (text.startsWith('true', i)) {
      i += 4;
      return true;
    }
    if (text.startsWith('false', i)) {
      i += 5;
      return false;
    }
    if (text.startsWith('null', i)) {
      i += 4;
      return null;
    }
    fail(`unexpected character "${c}"`);
  }

  function parseObject(): Record<string, unknown> {
    i++; // consume '{'
    const obj: Record<string, unknown> = {};
    const seen = new Set<string>();
    skipWs();
    if (text[i] === '}') {
      i++;
      return obj;
    }
    for (;;) {
      skipWs();
      if (text[i] !== '"') fail('expected a string member name');
      const key = parseString();
      if (seen.has(key)) fail(`duplicate member name ${JSON.stringify(key)}`);
      seen.add(key);
      skipWs();
      if (text[i] !== ':') fail('expected ":" after member name');
      i++;
      const value = parseValue();
      obj[key] = value;
      skipWs();
      if (text[i] === ',') {
        i++;
        continue;
      }
      if (text[i] === '}') {
        i++;
        break;
      }
      fail('expected "," or "}"');
    }
    return obj;
  }

  function parseArray(): unknown[] {
    i++; // consume '['
    const arr: unknown[] = [];
    skipWs();
    if (text[i] === ']') {
      i++;
      return arr;
    }
    for (;;) {
      arr.push(parseValue());
      skipWs();
      if (text[i] === ',') {
        i++;
        continue;
      }
      if (text[i] === ']') {
        i++;
        break;
      }
      fail('expected "," or "]"');
    }
    return arr;
  }

  function parseString(): string {
    i++; // consume opening quote
    let out = '';
    while (i < n) {
      const c = text[i]!;
      if (c === '"') {
        i++;
        return out;
      }
      if (c === '\\') {
        i++;
        const esc = text[i];
        switch (esc) {
          case '"':
            out += '"';
            break;
          case '\\':
            out += '\\';
            break;
          case '/':
            out += '/';
            break;
          case 'b':
            out += '\b';
            break;
          case 'f':
            out += '\f';
            break;
          case 'n':
            out += '\n';
            break;
          case 'r':
            out += '\r';
            break;
          case 't':
            out += '\t';
            break;
          case 'u': {
            const hex = text.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('invalid \\u escape');
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            fail(`invalid escape sequence "\\${esc}"`);
        }
        i++;
      } else if (c.charCodeAt(0) < 0x20) {
        fail('unescaped control character in string');
      } else {
        out += c;
        i++;
      }
    }
    fail('unterminated string');
  }

  function parseNumber(): number {
    const start = i;
    if (text[i] === '-') i++;
    if (text[i] === '0') {
      i++;
    } else if (text[i]! >= '1' && text[i]! <= '9') {
      while (text[i]! >= '0' && text[i]! <= '9') i++;
    } else {
      fail('invalid number');
    }
    if (text[i] === '.') {
      i++;
      if (!(text[i]! >= '0' && text[i]! <= '9')) fail('invalid number (digit expected after ".")');
      while (text[i]! >= '0' && text[i]! <= '9') i++;
    }
    if (text[i] === 'e' || text[i] === 'E') {
      i++;
      if (text[i] === '+' || text[i] === '-') i++;
      if (!(text[i]! >= '0' && text[i]! <= '9')) fail('invalid number (digit expected in exponent)');
      while (text[i]! >= '0' && text[i]! <= '9') i++;
    }
    return Number(text.slice(start, i));
  }

  const result = parseValue();
  skipWs();
  if (i !== n) fail('trailing characters after JSON value');
  return result;
}
