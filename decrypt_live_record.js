const fs = require('fs');
const crypto = require('crypto');

const sourcePath = './encryptionLiveRecordList.txt';
const outputPath = './encryptionLiveRecordList.decrypted.json';

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

const encryptedBase64 = fs.readFileSync(sourcePath, 'utf8').trim();
const encrypted = Buffer.from(encryptedBase64, 'base64');

const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

fs.writeFileSync(outputPath, decrypted.toString('utf8'));

console.log('AES key (utf8):', key.toString('utf8'));
console.log('AES key (hex):', key.toString('hex'));
console.log('Wrote:', outputPath);
