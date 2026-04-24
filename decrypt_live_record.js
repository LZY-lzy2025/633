const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const groups = [
  [0x59, 0x44, 0x79, 0x61],
  [0x78, 0x06, 0x5e, 0x7e],
  [0x60, 0x33, 0x1a, 0x19],
  [0x28, 0x4f, 0x1b, 0x20]
];
const xorBytes = [0x12, 0x34, 0x56, 0x78];

const key = Buffer.from(
  groups.flatMap((group, index) =>
    group.map((value) => ((value + 0x100) ^ xorBytes[index]) & 0xff)
  )
);

function decryptBase64AesEcb(base64Content) {
  const encrypted = Buffer.from(base64Content.trim(), 'base64');
  const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

function decryptFile(sourcePath, outputPath) {
  const encryptedBase64 = fs.readFileSync(sourcePath, 'utf8');
  const decryptedContent = decryptBase64AesEcb(encryptedBase64);
  fs.writeFileSync(outputPath, decryptedContent, 'utf8');
}

function buildOutputPath(inputFile) {
  const ext = path.extname(inputFile);
  const base = ext ? inputFile.slice(0, -ext.length) : inputFile;
  return `${base}.decrypted.json`;
}

function resolveInputFiles(args) {
  if (args.length > 0) {
    return args;
  }

  return fs
    .readdirSync('.')
    .filter((name) => /^\d+\.txt$/.test(name))
    .sort((a, b) => Number(a) - Number(b));
}

function main() {
  const inputFiles = resolveInputFiles(process.argv.slice(2));

  if (inputFiles.length === 0) {
    console.error('No input files found. Pass file paths or add files like 1.txt, 2.txt, ...');
    process.exit(1);
  }

  for (const inputFile of inputFiles) {
    const outputFile = buildOutputPath(inputFile);
    decryptFile(inputFile, outputFile);
    console.log(`Decrypted ${inputFile} -> ${outputFile}`);
  }

  console.log('AES key (utf8):', key.toString('utf8'));
  console.log('AES key (hex):', key.toString('hex'));
}

main();
