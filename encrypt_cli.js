#!/usr/bin/env node

// Instagram-style enc_password generator per PolarisEnvelopeEncryption:
// - Generate random 32-byte AES key
// - AES-256-GCM encrypt password with IV=12 zero bytes and AAD=timestamp (UTF-8)
// - Sealed-box (Curve25519) encrypt the raw AES key with server public key
// - Pack: [0x01][keyId(1)][sealedKeyLen(2 LE)][sealedKey][tag(16)][ciphertext]
// - Output: "#PWD_INSTAGRAM_BROWSER:<version>:<timestamp>:<base64(payload)>"
//
// Usage:
//   node encrypt_cli.js --password 'YourPass123'
//   node encrypt_cli.js -p 'YourPass123' --ts 1757900872
//   node encrypt_cli.js -p 'YourPass123' --key-id 78 --pub f8c86a4d0d92f87c01b9fb26aca4d60acf67f6fb517c28974d8e2b43ba60f74c --ver 10 --tag '#PWD_INSTAGRAM_BROWSER'

const crypto = require('crypto');

let sealedbox;
try {
  // Pure JS sealed box implementation compatible with NaCl box keys
  sealedbox = require('tweetnacl-sealedbox-js');
} catch (e) {
  console.error('Missing dependency: tweetnacl-sealedbox-js. Install with:');
  console.error('  npm i tweetnacl tweetnacl-sealedbox-js');
  process.exit(1);
}

const DEFAULTS = {
  keyId: 78,
  publicKeyHex: 'f8c86a4d0d92f87c01b9fb26aca4d60acf67f6fb517c28974d8e2b43ba60f74c',
  version: 10,
  tag: '#PWD_INSTAGRAM_BROWSER'
};

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--password' || a === '-p') args.password = argv[++i];
    else if (a === '--ts' || a === '-t') args.ts = argv[++i];
    else if (a === '--key-id') args.keyId = parseInt(argv[++i], 10);
    else if (a === '--pub') args.publicKeyHex = argv[++i];
    else if (a === '--ver') args.version = parseInt(argv[++i], 10);
    else if (a === '--tag') args.tag = argv[++i];
  }
  return args;
}

function hexToU8(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  const u8 = new Uint8Array(hex.length / 2);
  for (let i = 0; i < u8.length; i++) {
    u8[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return u8;
}

function aesGcmEncryptRawKeyZeroIv(aesKeyRaw32, plaintextBuf, aadBuf) {
  const iv = Buffer.alloc(12, 0); // 12 zero bytes
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKeyRaw32, iv);
  if (aadBuf && aadBuf.length) cipher.setAAD(aadBuf);
  const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return { ciphertext, tag };
}

function encryptEnvelope({ keyId, publicKeyHex, password, tsStr }) {
  if (!password) throw new Error('password required');
  if (!/^[0-9]{10}$/.test(tsStr)) {
    // Browser uses seconds; keep as-is if caller passes other formats, but warn lightly
  }

  const serverPubHex = publicKeyHex.trim().toLowerCase();
  if (serverPubHex.length !== 64) {
    throw new Error('public_key must be 32 bytes (64 hex chars)');
  }
  const serverPubU8 = hexToU8(serverPubHex); // 32 bytes

  // 1) Random AES-256 key (raw 32 bytes)
  const aesKeyRaw = crypto.randomBytes(32);

  // 2) AES-GCM encrypt password with zero IV and AAD = timestamp (UTF-8)
  const pwdBuf = Buffer.from(password, 'utf8');
  const tsBuf = Buffer.from(tsStr, 'utf8');
  const { ciphertext, tag } = aesGcmEncryptRawKeyZeroIv(aesKeyRaw, pwdBuf, tsBuf);

  // 3) Sealed-box encrypt the raw AES key with server public key
  const sealed = sealedbox.seal(aesKeyRaw, serverPubU8); // Uint8Array

  // 4) Pack: [0x01][keyId][len(2 LE)][sealed][tag][ciphertext]
  const sealedLen = sealed.length; // expected 32 + overhead (48) = 80
  const outLen = 1 + 1 + 2 + sealedLen + 16 + ciphertext.length;
  const out = Buffer.allocUnsafe(outLen);
  let u = 0;
  out[u++] = 0x01;
  out[u++] = keyId & 0xff;
  out[u++] = sealedLen & 0xff;           // length LE
  out[u++] = (sealedLen >> 8) & 0xff;
  out.set(Buffer.from(sealed), u); u += sealedLen;
  out.set(tag, u); u += 16;              // tag first
  out.set(ciphertext, u); u += ciphertext.length;

  return out.toString('base64');
}

async function main() {
  const args = parseArgs(process.argv);

  const password = args.password;
  if (!password) {
    console.error('Missing --password|-p');
    process.exit(1);
  }

  const keyId = Number.isInteger(args.keyId) ? args.keyId : DEFAULTS.keyId;
  const publicKeyHex = args.publicKeyHex || DEFAULTS.publicKeyHex;
  const version = Number.isInteger(args.version) ? args.version : DEFAULTS.version;
  const tag = args.tag || DEFAULTS.tag;

  const ts = args.ts || String(Math.floor(Date.now() / 1000));

  const b64 = encryptEnvelope({
    keyId,
    publicKeyHex,
    password,
    tsStr: ts
  });

  const encPassword = [tag, version, ts, b64].join(':');
  console.log(encPassword);
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}