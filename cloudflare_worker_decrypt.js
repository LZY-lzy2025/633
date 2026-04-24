const groups = [
  [0x59, 0x44, 0x79, 0x61],
  [0x78, 0x06, 0x5e, 0x7e],
  [0x60, 0x33, 0x1a, 0x19],
  [0x28, 0x4f, 0x1b, 0x20]
];
const xorBytes = [0x12, 0x34, 0x56, 0x78];

function buildKeyBytes() {
  return new Uint8Array(
    groups.flatMap((group, index) =>
      group.map((value) => ((value + 0x100) ^ xorBytes[index]) & 0xff)
    )
  );
}

function keyBytesToUtf8(keyBytes) {
  return new TextDecoder().decode(keyBytes);
}

function base64ToBytes(base64Content) {
  const binary = atob(base64Content.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function gfMul(a, b) {
  let p = 0;
  let aa = a;
  let bb = b;
  for (let i = 0; i < 8; i += 1) {
    if (bb & 1) {
      p ^= aa;
    }
    const hiBit = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (hiBit) {
      aa ^= 0x1b;
    }
    bb >>= 1;
  }
  return p;
}

function gfPow(a, n) {
  let result = 1;
  let base = a;
  let exp = n;

  while (exp > 0) {
    if (exp & 1) {
      result = gfMul(result, base);
    }
    base = gfMul(base, base);
    exp >>= 1;
  }

  return result;
}

function rotl8(value, shift) {
  return ((value << shift) | (value >> (8 - shift))) & 0xff;
}

function buildSboxTables() {
  const sbox = new Uint8Array(256);
  const invSbox = new Uint8Array(256);

  for (let i = 0; i < 256; i += 1) {
    const inv = i === 0 ? 0 : gfPow(i, 254);
    const transformed =
      inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63;
    sbox[i] = transformed;
    invSbox[transformed] = i;
  }

  return { sbox, invSbox };
}

function keyExpansion128(key, sbox) {
  const expanded = new Uint8Array(176);
  expanded.set(key);

  const rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
  const temp = new Uint8Array(4);

  let bytesGenerated = 16;
  let rconIndex = 1;

  while (bytesGenerated < 176) {
    for (let i = 0; i < 4; i += 1) {
      temp[i] = expanded[bytesGenerated - 4 + i];
    }

    if (bytesGenerated % 16 === 0) {
      const first = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = first;

      for (let i = 0; i < 4; i += 1) {
        temp[i] = sbox[temp[i]];
      }
      temp[0] ^= rcon[rconIndex];
      rconIndex += 1;
    }

    for (let i = 0; i < 4; i += 1) {
      expanded[bytesGenerated] = expanded[bytesGenerated - 16] ^ temp[i];
      bytesGenerated += 1;
    }
  }

  return expanded;
}

function addRoundKey(state, expandedKey, round) {
  const offset = round * 16;
  for (let i = 0; i < 16; i += 1) {
    state[i] ^= expandedKey[offset + i];
  }
}

function invShiftRows(state) {
  const s1 = state[1];
  state[1] = state[13];
  state[13] = state[9];
  state[9] = state[5];
  state[5] = s1;

  const s2 = state[2];
  const s6 = state[6];
  state[2] = state[10];
  state[6] = state[14];
  state[10] = s2;
  state[14] = s6;

  const s3 = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = s3;
}

function invSubBytes(state, invSbox) {
  for (let i = 0; i < 16; i += 1) {
    state[i] = invSbox[state[i]];
  }
}

function invMixColumns(state) {
  for (let col = 0; col < 4; col += 1) {
    const i = col * 4;
    const s0 = state[i];
    const s1 = state[i + 1];
    const s2 = state[i + 2];
    const s3 = state[i + 3];

    state[i] = gfMul(s0, 14) ^ gfMul(s1, 11) ^ gfMul(s2, 13) ^ gfMul(s3, 9);
    state[i + 1] = gfMul(s0, 9) ^ gfMul(s1, 14) ^ gfMul(s2, 11) ^ gfMul(s3, 13);
    state[i + 2] = gfMul(s0, 13) ^ gfMul(s1, 9) ^ gfMul(s2, 14) ^ gfMul(s3, 11);
    state[i + 3] = gfMul(s0, 11) ^ gfMul(s1, 13) ^ gfMul(s2, 9) ^ gfMul(s3, 14);
  }
}

function decryptAes128Ecb(bytes, keyBytes) {
  const { sbox, invSbox } = buildSboxTables();
  const expandedKey = keyExpansion128(keyBytes, sbox);
  const output = new Uint8Array(bytes.length);

  for (let offset = 0; offset < bytes.length; offset += 16) {
    const state = bytes.slice(offset, offset + 16);

    addRoundKey(state, expandedKey, 10);
    for (let round = 9; round >= 1; round -= 1) {
      invShiftRows(state);
      invSubBytes(state, invSbox);
      addRoundKey(state, expandedKey, round);
      invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state, invSbox);
    addRoundKey(state, expandedKey, 0);

    output.set(state, offset);
  }

  return output;
}

function removePkcs7Padding(data) {
  if (data.length === 0) {
    throw new Error('解密结果为空');
  }

  const pad = data[data.length - 1];
  if (pad < 1 || pad > 16 || pad > data.length) {
    throw new Error('PKCS7 padding不合法');
  }

  for (let i = data.length - pad; i < data.length; i += 1) {
    if (data[i] !== pad) {
      throw new Error('PKCS7 padding校验失败');
    }
  }

  return data.slice(0, data.length - pad);
}

function decryptBase64AesEcb(base64Content, keyBytes) {
  const encrypted = base64ToBytes(base64Content);

  if (encrypted.length % 16 !== 0) {
    throw new Error('密文长度不是16字节对齐，无法按AES-ECB解密');
  }

  const decrypted = decryptAes128Ecb(encrypted, keyBytes);
  const unpadded = removePkcs7Padding(decrypted);
  return new TextDecoder().decode(unpadded);
}

function readEncryptedPayload(body, contentType) {
  if (contentType.includes('application/json')) {
    const obj = JSON.parse(body);
    if (typeof obj === 'string') {
      return obj;
    }

    const candidateKeys = ['data', 'payload', 'encrypted', 'ciphertext', 'content'];
    for (const key of candidateKeys) {
      if (typeof obj?.[key] === 'string') {
        return obj[key];
      }
    }

    throw new Error('JSON响应中没有找到可解密字符串，请检查字段名');
  }

  return body;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*'
    }
  });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,OPTIONS',
          'access-control-allow-headers': '*'
        }
      });
    }

    try {
      const url = new URL(request.url);
      const target = url.searchParams.get('url') || env.ENCRYPTED_API_URL;

      if (!target) {
        return jsonResponse(
          { error: '缺少接口地址。请在查询参数传 ?url=... 或配置 ENCRYPTED_API_URL' },
          400
        );
      }

      const upstreamResp = await fetch(target, {
        headers: {
          Accept: 'application/json, text/plain;q=0.9, */*;q=0.8'
        }
      });

      if (!upstreamResp.ok) {
        return jsonResponse(
          { error: `上游接口请求失败: ${upstreamResp.status} ${upstreamResp.statusText}` },
          502
        );
      }

      const body = await upstreamResp.text();
      const contentType = upstreamResp.headers.get('content-type') || '';
      const encryptedText = readEncryptedPayload(body, contentType);

      const keyBytes = buildKeyBytes();
      const keyUtf8 = keyBytesToUtf8(keyBytes);
      const decryptedText = decryptBase64AesEcb(encryptedText, keyBytes);

      let parsed;
      try {
        parsed = JSON.parse(decryptedText);
      } catch {
        parsed = { decryptedText };
      }

      return jsonResponse({
        keyUtf8,
        sourceUrl: target,
        decrypted: parsed
      });
    } catch (error) {
      return jsonResponse(
        {
          error: '解密失败',
          message: error instanceof Error ? error.message : String(error)
        },
        500
      );
    }
  }
};
