import { strictEqual, throws } from 'node:assert';
import { describe, it } from '@paulmillr/jsbt/test.js';
import {
  formatWordDiff,
  UPSTREAM_COMMIT,
  validateTxtContent,
  WORDLISTS,
} from './fetch-wordlist.js';

describe('fetch-wordlist', () => {
  const words = Array.from({ length: 2048 }, (_, i) => `word-${i}`);
  const expected = { first: words[0], last: words.at(-1) };

  it('uses an immutable upstream commit and complete integrity metadata', () => {
    strictEqual(/^[0-9a-f]{40}$/.test(UPSTREAM_COMMIT), true);
    strictEqual(Object.keys(WORDLISTS).length, 10);
    for (const wordlist of Object.values(WORDLISTS)) {
      strictEqual(/^[0-9a-f]{64}$/.test(wordlist.sha256), true);
      strictEqual(typeof wordlist.first, 'string');
      strictEqual(typeof wordlist.last, 'string');
    }
  });

  it('accepts exactly 2048 unique words with known sentinels', () => {
    strictEqual(validateTxtContent(words.join('\n'), expected).length, 2048);
  });

  it('rejects duplicate words even when the list still has 2048 entries', () => {
    const duplicate = [...words];
    duplicate[123] = duplicate[122];
    throws(() => validateTxtContent(duplicate.join('\n'), expected), /Duplicate word/);
  });

  it('rejects unexpected sentinel words', () => {
    throws(
      () => validateTxtContent(words.join('\n'), { ...expected, first: 'canonical-first' }),
      /Unexpected first word/
    );
    throws(
      () => validateTxtContent(words.join('\n'), { ...expected, last: 'canonical-last' }),
      /Unexpected last word/
    );
  });

  it('formats changes by one-based wordlist index', () => {
    strictEqual(formatWordDiff(['one', 'two'], ['one', 'three']), '-    2: two\n+    2: three');
    strictEqual(formatWordDiff(words, words), '');
  });
});

it.runWhen(import.meta.url);
