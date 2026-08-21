#!/usr/bin/env node

import { strictEqual } from 'node:assert';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join as pjoin } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { pathToFileURL } from 'node:url';

// The wordlists are frozen by BIP-39. This is the bitcoin/bips commit that added the
// final list we ship (Portuguese), after all earlier canonical list corrections.
export const UPSTREAM_COMMIT = 'd353c54154bac64a88eb18cf2d47d15ead083de4';
const UPSTREAM_BASE_URL = `https://raw.githubusercontent.com/bitcoin/bips/${UPSTREAM_COMMIT}/bip-0039`;

// SHA-256 covers the exact upstream UTF-8 file, including its single trailing LF.
// Changing the pin or any digest requires independently auditing every affected list.
export const WORDLISTS = Object.freeze({
  chinese_simplified: {
    file: 'simplified-chinese',
    title: 'Simplified Chinese',
    sha256: '5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726',
    first: '的',
    last: '歇',
  },
  chinese_traditional: {
    file: 'traditional-chinese',
    title: 'Traditional Chinese',
    sha256: '417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f',
    first: '的',
    last: '歇',
  },
  czech: {
    file: 'czech',
    title: 'Czech',
    sha256: '7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc',
    first: 'abdikace',
    last: 'zvyk',
  },
  english: {
    file: 'english',
    title: 'English',
    sha256: '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda',
    first: 'abandon',
    last: 'zoo',
  },
  french: {
    file: 'french',
    title: 'French',
    sha256: 'ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59',
    first: 'abaisser',
    last: 'zoologie',
  },
  italian: {
    file: 'italian',
    title: 'Italian',
    sha256: 'd392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2',
    first: 'abaco',
    last: 'zuppa',
  },
  japanese: {
    file: 'japanese',
    title: 'Japanese',
    sha256: '2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd',
    first: 'あいこくしん',
    last: 'われる',
  },
  korean: {
    file: 'korean',
    title: 'Korean',
    sha256: '9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60',
    first: '가격',
    last: '힘껏',
  },
  portuguese: {
    file: 'portuguese',
    title: 'Portuguese',
    sha256: '2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f',
    first: 'abacate',
    last: 'zumbido',
  },
  spanish: {
    file: 'spanish',
    title: 'Spanish',
    sha256: '46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b',
    first: 'ábaco',
    last: 'zurdo',
  },
});

export function validateTxtContent(txtContent, expected) {
  const words = txtContent.split('\n');
  const emptyLine = words.findIndex((word) => word.trim() === '');
  strictEqual(emptyLine, -1, `Empty word at line ${emptyLine + 1}`);
  strictEqual(words.length, 2048, 'Wordlist must contain exactly 2048 words');

  const seen = new Set();
  for (const [index, word] of words.entries()) {
    strictEqual(seen.has(word), false, `Duplicate word at line ${index + 1}: ${word}`);
    seen.add(word);
  }
  strictEqual(words[0], expected.first, 'Unexpected first word');
  strictEqual(words.at(-1), expected.last, 'Unexpected last word');
  return words;
}

function wordlistFromTs(tsContent) {
  const match = tsContent.match(/`([\s\S]*?)`\.split\('\\n'\)/);
  if (match === null) throw new Error('Could not read the existing generated wordlist');
  return match[1].split('\n');
}

export function formatWordDiff(currentWords, fetchedWords) {
  const changes = [];
  const length = Math.max(currentWords.length, fetchedWords.length);
  for (let i = 0; i < length; i++) {
    if (currentWords[i] === fetchedWords[i]) continue;
    const line = String(i + 1).padStart(4, ' ');
    changes.push(`- ${line}: ${currentWords[i] ?? '<missing>'}`);
    changes.push(`+ ${line}: ${fetchedWords[i] ?? '<missing>'}`);
  }
  return changes.join('\n');
}

async function confirmOverwrite(target) {
  const readline = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await readline.question(`Type "yes" to overwrite ${target}: `);
    return answer === 'yes';
  } finally {
    readline.close();
  }
}

export async function main(language = process.argv[2]) {
  if (language === undefined || !Object.hasOwn(WORDLISTS, language)) {
    throw new Error(`Supply one of: ${Object.keys(WORDLISTS).join(', ')}`);
  }
  const expected = WORDLISTS[language];
  const url = `${UPSTREAM_BASE_URL}/${language}.txt`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Fetch (${url}) failed: HTTP ${response.status}`);
  const downloaded = new Uint8Array(await response.arrayBuffer());
  const digest = createHash('sha256').update(downloaded).digest('hex');
  strictEqual(digest, expected.sha256, `SHA-256 mismatch for ${language}`);
  const txtContent = new TextDecoder('utf8', { fatal: true }).decode(downloaded);

  strictEqual(txtContent.endsWith('\n'), true, 'Upstream file must end in LF');
  strictEqual(txtContent.endsWith('\n\n'), false, 'Upstream file must have one trailing LF');
  strictEqual(txtContent.includes('\r'), false, 'Upstream file must use LF line endings');
  const wordlist = txtContent.slice(0, -1);
  const fetchedWords = validateTxtContent(wordlist, expected);

  const target = pjoin(import.meta.dirname, '..', '..', 'src', 'wordlists', `${expected.file}.ts`);
  const currentWords = wordlistFromTs(await readFile(target, 'utf8'));
  const diff = formatWordDiff(currentWords, fetchedWords);
  if (diff === '') {
    console.log(`${expected.title} wordlist already matches pinned upstream ${UPSTREAM_COMMIT}.`);
    return;
  }

  console.log(`Word-level diff for ${target}:\n${diff}`);
  if (!(await confirmOverwrite(target))) {
    console.log('Aborted; no files were changed.');
    return;
  }

  const tsContent =
    `/** ${expected.title} BIP39 wordlist. */\n` +
    `export const wordlist: string[] = /* @__PURE__ */ Object.freeze(\n` +
    `  \`${wordlist}\`.split('\\n')\n` +
    `) as string[];\n`;
  await writeFile(target, tsContent, 'utf8');
  console.log(`Wrote ${target}. Review and commit the diff.`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
