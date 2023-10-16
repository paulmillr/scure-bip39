#!/usr/bin/env node

// dependencies
const path = require('path');
const fs = require('fs');
const util = require('util');
const assert = require('assert');
const writeFileAsync = util.promisify(fs.writeFile);

// arguments
const language = process.argv[2];
if (language === undefined) {
  console.error('Supply language (lower cased) argument.');
  process.exit();
}

// fetch and save file
(async () => {
  try {
    // fetch
    const url = `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/${language}.txt`;
    const response = await fetch(url);
    if (response.ok === false) throw new Error(`Fetch (${url}) failed`);
    const txtContent = await response.text();

    // remove trailing line breaks
    const wordlist = txtContent.replace(/\n+$/, '');

    // validate .txt file content
    validateTxtContent(wordlist);

    // write .ts file
    const tsContent = `export const wordlist: string[] = \`${wordlist}\`.split('\\n');\n`;
    await writeFileAsync(path.join(__dirname, '..', 'src/wordlists', `${language}.ts`), tsContent);
  } catch (err) {
    console.error(err);
  }
})();

const validateTxtContent = (txtContent) => {
  const words = txtContent.split('\n');
  const emptyLines = words.filter((word) => word.trim() === '');
  assert.equal(emptyLines.length, 0);
  assert.equal(words.length, 2048);
};
