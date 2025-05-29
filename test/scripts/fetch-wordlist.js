#!/usr/bin/env node

// dependencies
import { equal } from 'node:assert';
import { writeFile } from 'node:fs/promises';
import { join as pjoin } from 'node:path';

// arguments
const arg = process.argv[2];
if (arg === undefined) {
  console.error('Supply language (lowercased, snakecased) argument.');
  process.exit();
}

// parse language argument
const filenameSnakeCased = arg;
const parts = arg.split('_');
let filenameKebabCased = parts.length > 1 ? `${parts[1]}-${parts[0]}` : arg;

// fetch, validate and save file
(async () => {
  try {
    // fetch
    const url = `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/${filenameSnakeCased}.txt`;
    const response = await fetch(url);
    if (response.ok === false) throw new Error(`Fetch (${url}) failed`);
    const txtContent = await response.text();

    // remove trailing line breaks
    const wordlist = txtContent.replace(/\n+$/, '');

    // validate .txt file content
    validateTxtContent(wordlist);

    // chinese_simplified => simplified-chinese.js
    // chinese_traditional => traditional-chinese.js
    let varName = filenameSnakeCased;
    if (filenameSnakeCased === 'chinese_simplified') {
      filenameKebabCased = 'simplified-chinese';
      varName = 'simplifiedChinese';
    }
    if (filenameSnakeCased === 'chinese_traditional') {
      filenameKebabCased = 'traditional-chinese';
      varName = 'traditionalChinese';
    }

    // Force this for now
    varName = 'wordlist';

    // write .ts file
    const tsContent = `export const ${varName}: string[] = \`${wordlist}\`.split('\\n');\n`;
    await writeFile(
      pjoin(import.meta.dirname, '..', '..', 'src', 'wordlists', `${filenameKebabCased}.ts`),
      tsContent
    );
  } catch (err) {
    console.error(err);
  }
})();

// assertions
const validateTxtContent = (txtContent) => {
  const words = txtContent.split('\n');
  const emptyLines = words.filter((word) => word.trim() === '');
  equal(emptyLines.length, 0);
  equal(words.length, 2048);
};
