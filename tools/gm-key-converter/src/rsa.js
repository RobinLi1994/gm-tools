import CryptoJS from 'crypto-js/core.js';
import 'crypto-js/lib-typedarrays.js';
import 'crypto-js/tripledes.js';
import { pow } from '@noble/curves/abstract/modular';

const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const unhex = text => Uint8Array.from(text.match(/../g), byte => parseInt(byte, 16));

/**
 * RFC 8017 §7.2.1：以非零随机填充编码会话密钥，再执行 RSA 公钥模幂运算。
 * 这里只使用公开指数，不能将此函数改作私钥运算或解密。
 */
function wrapSessionKey(signing, session) {
  const encoded = new Uint8Array(signing.bits / 8);
  const separator = encoded.length - session.length - 1;
  if (separator < 10) throw new Error('RSA 模数无法容纳会话密钥。');
  encoded[1] = 2;
  try {
    let offset = 2;
    while (offset < separator) {
      const random = crypto.getRandomValues(new Uint8Array(separator - offset));
      // 拒绝采样而非替换零字节，保持每个填充字节在 1..255 上均匀分布。
      for (const byte of random) if (byte !== 0) encoded[offset++] = byte;
      random.fill(0);
    }
    encoded.set(session, separator + 1);
    const message = BigInt('0x' + hex(encoded));
    if (message >= signing.n) throw new Error('RSA 编码超出模数范围。');
    const cipher = pow(message, signing.e, signing.n);
    return unhex(cipher.toString(16).padStart(encoded.length * 2, '0'));
  } finally { encoded.fill(0); }
}

/** 按现有项目兼容协议封装 PKCS#8；0x2002 与固定 IV 是既有设备约定。 */
export function wrapRsaPrivateKey(signing, pkcs8) {
  const session = crypto.getRandomValues(new Uint8Array(16));
  const expanded = new Uint8Array(24);
  expanded.set(session);
  expanded.set(session.subarray(0, 8), 16);
  const keyWords = CryptoJS.lib.WordArray.create(expanded);
  const privateWords = CryptoJS.lib.WordArray.create(pkcs8);
  try {
    const wrapped = wrapSessionKey(signing, session);
    // 传入原始 WordArray 密钥，明确使用 CBC/PKCS7，不经过口令派生或库内随机源。
    const encrypted = unhex(CryptoJS.TripleDES.encrypt(privateWords, keyWords, {
      iv: CryptoJS.enc.Hex.parse('0001020304050607'), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7,
    }).ciphertext.toString(CryptoJS.enc.Hex));
    if (wrapped.length !== signing.bits / 8 || encrypted.length === 0 || encrypted.length % 8 !== 0) {
      throw new Error('RSA 密钥保护结构的密文长度异常。');
    }
    const output = new Uint8Array(8 + wrapped.length + encrypted.length);
    const view = new DataView(output.buffer);
    view.setUint32(0, 0x2002, true);
    view.setUint32(4, wrapped.length, true);
    output.set(wrapped, 8);
    output.set(encrypted, 8 + wrapped.length);
    return output;
  } finally {
    session.fill(0);
    expanded.fill(0);
    keyWords.words.fill(0);
    privateWords.words.fill(0);
    pkcs8.fill(0);
  }
}
