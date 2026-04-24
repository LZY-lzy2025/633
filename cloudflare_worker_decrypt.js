import CryptoJS from 'crypto-js';

const groups = [
  [0x59, 0x44, 0x79, 0x61],
  [0x78, 0x06, 0x5e, 0x7e],
  [0x60, 0x33, 0x1a, 0x19],
  [0x28, 0x4f, 0x1b, 0x20]
];
const xorBytes = [0x12, 0x34, 0x56, 0x78];

function buildKeyUtf8() {
  const bytes = groups.flatMap((group, index) =>
    group.map((value) => ((value + 0x100) ^ xorBytes[index]) & 0xff)
  );
  return String.fromCharCode(...bytes);
}

function decryptBase64AesEcb(base64Content, keyUtf8) {
  const key = CryptoJS.enc.Utf8.parse(keyUtf8);
  const cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Base64.parse(base64Content.trim())
  });

  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  });

  return CryptoJS.enc.Utf8.stringify(decrypted);
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

      const keyUtf8 = buildKeyUtf8();
      const decryptedText = decryptBase64AesEcb(encryptedText, keyUtf8);

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
