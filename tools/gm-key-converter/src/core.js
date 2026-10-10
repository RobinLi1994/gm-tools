import { sm2, sm4 } from 'sm-crypto-v2';

export const MAX_INPUT_BYTES = 256 * 1024;
const EC_OID = '2a8648ce3d0201';
const SM2_OID = '2a811ccf5501822d';
const SM4_ECB_OID = '2a811ccf55016801';
const SM2_ORDER = BigInt('0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123');
const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
const unhex = (text) => Uint8Array.from(text.match(/../g) || [], (byte) => parseInt(byte, 16));
const requireValue = (condition, message) => { if (!condition) throw new Error(message); };

/** 拼接长度有界的二进制字段，不使用展开参数以避免大文件耗尽调用栈。 */
function concat(...parts) {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

/** 严格读取 DER 长度与嵌套边界；不接受 BER 不定长或尾随数据。 */
function parseDer(bytes) {
  let count = 0;
  function read(offset, end, depth) {
    requireValue(depth <= 24 && ++count <= 10000 && offset + 2 <= end, 'DER 结构损坏或嵌套过深。');
    const tag = bytes[offset++];
    requireValue((tag & 31) !== 31, 'DER 中含不支持的高位标签。');
    let length = bytes[offset++];
    if (length & 128) {
      const size = length & 127;
      requireValue(size > 0 && size <= 3 && offset + size <= end && bytes[offset] !== 0, 'DER 长度编码无效。');
      length = 0;
      for (let index = 0; index < size; index++) length = length * 256 + bytes[offset++];
      requireValue(length >= 128, 'DER 长度不是最短编码。');
    }
    const next = offset + length;
    requireValue(next <= end, 'DER 数据被截断或长度越界。');
    const node = { tag, value: bytes.subarray(offset, next), children: [] };
    if (tag & 32) {
      while (offset < next) {
        const child = read(offset, next, depth + 1);
        node.children.push(child.node);
        offset = child.next;
      }
    }
    return { node, next };
  }
  const result = read(0, bytes.length, 0);
  requireValue(result.next === bytes.length, 'DER 后存在多余数据，请只提供单个对象。');
  return result.node;
}

function tagged(node, tag, message = 'DER 字段类型不正确。') {
  requireValue(node?.tag === tag, message);
  return node;
}

/** PEM 只接受单个对象，避免误选证书链或混合私钥。 */
function decodePem(text, allowedLabels) {
  requireValue(typeof text === 'string' && text.length <= MAX_INPUT_BYTES, '输入为空或超过 256 KiB 限制。');
  if (/ENCRYPTED PRIVATE KEY|Proc-Type\s*:\s*4,ENCRYPTED|DEK-Info\s*:/i.test(text)) {
    throw new Error('暂不支持带密码的加密 PEM 私钥，请使用未加密的 PEM 私钥。');
  }
  requireValue((text.match(/-----BEGIN /g) || []).length <= 1, '请只提供一份 PEM 对象，不要粘贴证书链或多个文件。');
  const match = text.trim().match(/^-----BEGIN ([A-Z0-9 ]+)-----\s*([\s\S]*?)\s*-----END \1-----$/);
  requireValue(match && allowedLabels.includes(match[1]), `需要 ${allowedLabels.join(' 或 ')} 格式的 PEM。`);
  const encoded = match[2].replace(/\s/g, '');
  requireValue(encoded.length > 0 && encoded.length % 4 === 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded), 'PEM Base64 内容无效。');
  const binary = atob(encoded);
  requireValue(btoa(binary) === encoded, 'PEM Base64 编码不规范。');
  return { label: match[1], bytes: Uint8Array.from(binary, (character) => character.charCodeAt(0)) };
}

function checkCurve(algorithm) {
  const fields = tagged(algorithm, 0x30).children;
  requireValue(fields.length === 2 && hex(tagged(fields[0], 6).value) === EC_OID
    && hex(tagged(fields[1], 6).value) === SM2_OID, '仅支持命名曲线为 SM2（sm2p256v1）的证书或私钥。');
}

function publicKeyFromBits(node) {
  const bits = tagged(node, 3, '公钥 BIT STRING 结构无效。').value;
  requireValue(bits[0] === 0 && (bits.length === 66 || bits.length === 34), 'SM2 公钥长度或填充位无效。');
  const encoded = hex(bits.subarray(1));
  requireValue(sm2.verifyPublicKey(encoded), 'SM2 公钥不在有效曲线上。');
  return sm2.precomputePublicKey(encoded).toHex(false).toLowerCase();
}

/** 检查证书必需字段的结构，不将损坏输入误当作证书；不承担信任链验证。 */
function checkCertificateStructure(certificate) {
  const fail = '证书必需字段缺失或结构无效。';
  requireValue(certificate.children.length === 3, fail);
  const algorithm = (node) => {
    const fields = tagged(node, 0x30, fail).children;
    requireValue(fields.length >= 1 && fields.length <= 2 && tagged(fields[0], 6, fail).value.length > 0, fail);
  };
  algorithm(certificate.children[1]);
  const signature = tagged(certificate.children[2], 3, fail).value;
  requireValue(signature.length > 1 && signature[0] === 0, fail);
  const body = tagged(certificate.children[0], 0x30, fail).children;
  const offset = body[0]?.tag === 0xa0 ? 1 : 0;
  if (offset) {
    requireValue(body[0].children.length === 1, fail);
    const version = tagged(body[0].children[0], 2, fail).value;
    requireValue(version.length === 1 && version[0] <= 2, fail);
  }
  requireValue(body.length >= offset + 6, fail);
  const serial = tagged(body[offset], 2, fail).value;
  requireValue(serial.length > 0 && (serial[0] & 128) === 0, fail);
  algorithm(body[offset + 1]);
  for (const name of [body[offset + 2], body[offset + 4]]) {
    for (const set of tagged(name, 0x30, fail).children) {
      requireValue(tagged(set, 0x31, fail).children.length > 0, fail);
      for (const attribute of set.children) {
        const fields = tagged(attribute, 0x30, fail).children;
        requireValue(fields.length === 2 && tagged(fields[0], 6, fail).value.length > 0, fail);
      }
    }
  }
  const validity = tagged(body[offset + 3], 0x30, fail).children;
  requireValue(validity.length === 2, fail);
  for (const time of validity) {
    const text = new TextDecoder().decode(time.value);
    requireValue((time.tag === 23 && /^\d{12}Z$/.test(text)) || (time.tag === 24 && /^\d{14}Z$/.test(text)), fail);
  }
  return body[offset + 5];
}

/** 读取一张 PEM/DER 证书中的 SM2 公钥；此步骤不验证信任链或证书用途。 */
export function parseCertificate(input) {
  requireValue(input && input.length > 0, '请提供证书文件或 PEM 文本。');
  let bytes;
  if (typeof input === 'string') {
    bytes = decodePem(input, ['CERTIFICATE']).bytes;
  } else {
    requireValue(input instanceof Uint8Array && input.length <= MAX_INPUT_BYTES, '证书文件超过 256 KiB 或类型不支持。');
    const prefix = new TextDecoder().decode(input.subarray(0, 128)).trimStart();
    bytes = prefix.startsWith('-----BEGIN') ? decodePem(new TextDecoder().decode(input), ['CERTIFICATE']).bytes : input;
  }
  const certificate = tagged(parseDer(bytes), 0x30, '证书 DER 结构无效。');
  const spki = tagged(checkCertificateStructure(certificate), 0x30, '证书缺少公钥信息。').children;
  requireValue(spki.length === 2, '证书公钥结构无效。');
  checkCurve(spki[0]);
  return { publicKey: publicKeyFromBits(spki[1]) };
}

/** 解析未加密的 PKCS#8 / SEC1 PEM，并检查曲线、标量和可选公钥的一致性。 */
export function parsePrivateKey(input) {
  const { label, bytes } = decodePem(input, ['PRIVATE KEY', 'EC PRIVATE KEY']);
  let node = tagged(parseDer(bytes), 0x30);
  let inheritedCurve = false;
  if (label === 'PRIVATE KEY') {
    const fields = node.children;
    requireValue(fields.length >= 3 && fields.length <= 4 && hex(tagged(fields[0], 2).value) === '00', 'PKCS#8 私钥版本或字段无效。');
    checkCurve(fields[1]);
    inheritedCurve = true;
    node = tagged(parseDer(tagged(fields[2], 4).value), 0x30);
  }
  const fields = node.children;
  requireValue(fields.length >= 2 && fields.length <= 4 && hex(tagged(fields[0], 2).value) === '01', 'SEC1 私钥版本或字段无效。');
  const scalar = tagged(fields[1], 4).value;
  requireValue(scalar.length >= 1 && scalar.length <= 32, 'SM2 私钥标量长度无效。');
  const parameters = fields.filter((field) => field.tag === 0xa0);
  const publics = fields.filter((field) => field.tag === 0xa1);
  requireValue(parameters.length <= 1 && publics.length <= 1 && fields.slice(2).every((field) => field.tag === 0xa0 || field.tag === 0xa1), 'SEC1 私钥含重复或未知字段。');
  if (parameters.length) {
    requireValue(parameters[0].children.length === 1 && hex(tagged(parameters[0].children[0], 6).value) === SM2_OID, '私钥曲线必须为 SM2（sm2p256v1）。');
  } else {
    requireValue(inheritedCurve, 'SEC1 私钥缺少 SM2 命名曲线信息，请使用包含曲线信息的 PEM。');
  }
  const privateHex = hex(scalar).padStart(64, '0');
  const number = BigInt('0x' + privateHex);
  requireValue(number > 0n && number < SM2_ORDER, 'SM2 私钥标量超出有效范围。');
  if (publics.length) {
    requireValue(publics[0].children.length === 1 && publicKeyFromBits(publics[0].children[0]) === sm2.getPublicKeyFromPrivateKey(privateHex).toLowerCase(), '私钥内部的公钥与私钥标量不匹配。');
  }
  return privateHex;
}

/** DER 长度编码仅用于本工具生成的小型密钥保护结构。 */
function der(tag, value) {
  let length;
  if (value.length < 128) length = Uint8Array.of(value.length);
  else {
    let encoded = value.length.toString(16);
    if (encoded.length % 2) encoded = '0' + encoded;
    const size = unhex(encoded);
    length = concat(Uint8Array.of(128 | size.length), size);
  }
  return concat(Uint8Array.of(tag), length, value);
}

function positiveInteger(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  const value = bytes.subarray(start);
  return der(2, value[0] & 128 ? concat(Uint8Array.of(0), value) : value);
}

/** 使用签名公钥封装会话密钥；整数按小端存储，坐标保持大端，兼容现有 GmUtil。 */
export function convert({ signCert, encCert, privateKey, format }) {
  requireValue(format === '0016' || format === '0009', '请选择 GM0016 或 GM0009 格式。');
  requireValue(typeof globalThis.crypto?.getRandomValues === 'function', '浏览器不支持安全随机数，请使用新版 Chrome、Edge 或 Firefox。');
  let signing;
  let encryption;
  let scalar;
  try { signing = parseCertificate(signCert); } catch (error) { throw new Error('签名证书：' + error.message); }
  try { encryption = parseCertificate(encCert); } catch (error) { throw new Error('加密证书：' + error.message); }
  try { scalar = parsePrivateKey(privateKey); } catch (error) { throw new Error('加密私钥：' + error.message); }
  requireValue(sm2.getPublicKeyFromPrivateKey(scalar).toLowerCase() === encryption.publicKey, '加密私钥与加密证书不匹配，请检查是否选择了同一组文件。');
  const session = crypto.getRandomValues(new Uint8Array(16));
  const privateBytes = unhex(scalar);
  try {
    // 库返回的 C1C3C2 不带 04 点标记，直接拆成 X、Y、C3、C2。
    const encryptedSession = unhex(sm2.doEncrypt(session, signing.publicKey, 1));
    const encryptedPrivate = sm4.encrypt(privateBytes, session, { mode: 'ecb', padding: 'none', output: 'array' });
    requireValue(encryptedSession.length === 112 && encryptedPrivate.length === 32, '密码库返回的数据长度异常。');
    const publicBytes = unhex(encryption.publicKey);
    let output;
    if (format === '0016') {
      output = new Uint8Array(388);
      const view = new DataView(output.buffer);
      view.setUint32(0, 1, true);
      view.setUint32(4, 0x401, true);
      view.setUint32(8, 256, true);
      output.set(encryptedPrivate, 44);
      view.setUint32(76, 256, true);
      output.set(publicBytes.subarray(1, 33), 112);
      output.set(publicBytes.subarray(33), 176);
      output.set(encryptedSession.subarray(0, 32), 240);
      output.set(encryptedSession.subarray(32, 64), 304);
      output.set(encryptedSession.subarray(64, 96), 336);
      view.setUint32(368, 16, true);
      output.set(encryptedSession.subarray(96), 372);
    } else {
      const encryptedKey = der(0x30, concat(positiveInteger(encryptedSession.subarray(0, 32)),
        positiveInteger(encryptedSession.subarray(32, 64)), der(4, encryptedSession.subarray(64, 96)),
        der(4, encryptedSession.subarray(96))));
      output = der(0x30, concat(der(0x30, der(6, unhex(SM4_ECB_OID))), encryptedKey,
        der(3, concat(Uint8Array.of(0), publicBytes)), der(3, concat(Uint8Array.of(0), encryptedPrivate))));
    }
    return { base64: btoa(String.fromCharCode(...output)), byteLength: output.length, format };
  } finally {
    session.fill(0);
    privateBytes.fill(0);
  }
}
