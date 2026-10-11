import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { sm2, sm4 } from 'sm-crypto-v2';
import { convert, parseCertificate, parsePrivateKey } from '../src/core.js';

const fixtureDir = new URL('../build/fixtures/', import.meta.url);
const read = (name) => readFileSync(new URL(name, fixtureDir));
const text = (name) => read(name).toString();
const inputs = () => ({ signCert: text('sign.pem'), encCert: text('enc.pem'), privateKey: text('enc.key') });
const hex = (value) => Buffer.from(value).toString('hex');

test('PEM / DER 证书、PKCS#8 / SEC1 私钥识别为同一 SM2 密钥', () => {
  assert.equal(parseCertificate(text('enc.pem')).publicKey, parseCertificate(read('enc.der')).publicKey);
  assert.equal(parsePrivateKey(text('enc.key')), parsePrivateKey(text('enc-sec1.key')));
  assert.equal(sm2.getPublicKeyFromPrivateKey(parsePrivateKey(text('enc.key'))), parseCertificate(text('enc.pem')).publicKey);
});

test('GM0016 小端结构可以解封回原始私钥', () => {
  const result = convert({ ...inputs(), format: '0016' });
  const bytes = Buffer.from(result.base64, 'base64');
  assert.equal(bytes.length, 388);
  assert.equal(bytes.readUInt32LE(0), 1);
  assert.equal(bytes.readUInt32LE(4), 0x401);
  assert.equal(bytes.readUInt32LE(8), 256);
  assert.equal(bytes.readUInt32LE(76), 256);
  assert.equal(bytes.readUInt32LE(368), 16);
  for (const start of [12, 80, 144, 208, 272]) assert.deepEqual(bytes.subarray(start, start + 32), Buffer.alloc(32));
  assert.equal('04' + hex(bytes.subarray(112, 144)) + hex(bytes.subarray(176, 208)), parseCertificate(text('enc.pem')).publicKey);
  const cipher = hex(Buffer.concat([bytes.subarray(240, 272), bytes.subarray(304, 336), bytes.subarray(336, 368), bytes.subarray(372)]));
  const sessionKey = sm2.doDecrypt(cipher, parsePrivateKey(text('sign.key')), 1, { output: 'array' });
  const decrypted = sm4.decrypt(bytes.subarray(44, 76), sessionKey, { mode: 'ecb', padding: 'none', output: 'array' });
  assert.equal(hex(decrypted), parsePrivateKey(text('enc.key')));
});

test('两种格式均经 Java/BouncyCastle 解析、解密并核对私钥和公钥', () => {
  for (const format of ['0016', '0009']) {
    const result = convert({ ...inputs(), format });
    writeFileSync(new URL(`output-${format}.key`, fixtureDir), result.base64);
  }
  const classpath = text('classpath.txt').trim();
  const output = execFileSync('java', ['--class-path', classpath, new URL('GmInterop.java', import.meta.url).pathname, 'verify', fixtureDir.pathname], { encoding: 'utf8' });
  assert.match(output, /GM0016 和 GM0009 交叉解密验证通过/);
});

test('随机封装使重复转换产生不同密文', () => {
  for (const format of ['0016', '0009']) {
    assert.notEqual(convert({ ...inputs(), format }).base64, convert({ ...inputs(), format }).base64);
  }
});

test('不匹配、非 SM2、带密码私钥及错误格式给出明确错误', () => {
  assert.throws(() => convert({ ...inputs(), privateKey: text('sign.key'), format: '0016' }), /不匹配/);
  assert.throws(() => parseCertificate(text('p256.pem')), /SM2/);
  assert.throws(() => parsePrivateKey(text('p256.key')), /SM2/);
  assert.throws(() => parsePrivateKey('-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----'), /密码|加密/);
  assert.throws(() => convert({ ...inputs(), format: '0019' }), /格式/);
  assert.throws(() => parseCertificate(''), /证书/);
  assert.throws(() => parsePrivateKey('hello'), /PEM/);
});

test('拒绝截断 DER、多份证书、越界长度和不合法 Base64', () => {
  assert.throws(() => parseCertificate(read('enc.der').subarray(0, 30)), /DER|证书/);
  assert.throws(() => parseCertificate(text('enc.pem') + text('sign.pem')), /一份|单个/);
  assert.throws(() => parseCertificate(new Uint8Array([0x30, 0x84, 0xff, 0xff, 0xff, 0xff])), /DER/);
  assert.throws(() => parseCertificate('-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----'), /Base64/);
});

test('拒绝含有效公钥但缺少 X.509 必需字段的伪证书', () => {
  const tlv = (tag, content) => Buffer.concat([Buffer.from([tag, content.length]), content]);
  const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
  const pub = Buffer.from(parseCertificate(text('enc.pem')).publicKey, 'hex');
  const algorithm = seq(tlv(6, Buffer.from('2a8648ce3d0201', 'hex')), tlv(6, Buffer.from('2a811ccf5501822d', 'hex')));
  const spki = seq(algorithm, tlv(3, Buffer.concat([Buffer.from([0]), pub])));
  // issuer、validity、subject 被错误编码为 OCTET STRING；单纯找 SPKI 会误接受。
  const body = seq(tlv(2, Buffer.from([1])), seq(), tlv(4, Buffer.alloc(0)), tlv(4, Buffer.alloc(0)), tlv(4, Buffer.alloc(0)), spki);
  const invalidCertificate = seq(body, seq(), tlv(3, Buffer.from([0])));
  assert.throws(() => parseCertificate(invalidCertificate), /证书/);
});


test('RSA 证书 PEM/DER 与 PKCS#1/PKCS#8 私钥识别并归一化', () => {
  for (const bits of [2048, 3072, 4096]) {
    const name = `rsa-enc-${bits}`;
    const cert = parseCertificate(text(name + '.pem'));
    assert.equal(cert.algorithm, 'RSA');
    assert.equal(cert.bits, bits);
    assert.deepEqual(cert, parseCertificate(read(name + '.der')));
    const key = parsePrivateKey(text(name + '.key'));
    const pkcs1 = parsePrivateKey(text(name + '-pkcs1.key'));
    assert.equal(key.algorithm, 'RSA');
    assert.equal(key.n, cert.n);
    assert.equal(key.e, cert.e);
    assert.deepEqual(key.pkcs8, pkcs1.pkcs8);
    assert.deepEqual(Buffer.from(key.pkcs8), read(name + '-pkcs8.der'));
  }
});

test('RSA GM0016 兼容结构由 BouncyCastle 独立解封并验证私钥可签名', () => {
  for (const bits of [2048, 3072, 4096]) {
    for (const encoding of ['key', 'pkcs1.key']) {
      const keyName = encoding === 'key' ? `rsa-enc-${bits}.key` : `rsa-enc-${bits}-pkcs1.key`;
      const result = convert({ signCert: text('rsa-sign.pem'), encCert: text(`rsa-enc-${bits}.pem`),
        privateKey: text(keyName), format: '0016' });
      assert.equal(result.algorithm, 'RSA');
      const bytes = Buffer.from(result.base64, 'base64');
      assert.equal(bytes.readUInt32LE(0), 0x2002);
      assert.equal(bytes.readUInt32LE(4), 256);
      assert.equal((bytes.length - 264) % 8, 0);
      writeFileSync(new URL(`rsa-output-${bits}-${encoding}`, fixtureDir), result.base64);
    }
  }
  const result = convert({ signCert: text('rsa-enc-4096.pem'), encCert: text('rsa-enc-2048.pem'),
    privateKey: text('rsa-enc-2048.key'), format: '0016' });
  assert.equal(Buffer.from(result.base64, 'base64').readUInt32LE(4), 512);
  writeFileSync(new URL('rsa-output-large-sign', fixtureDir), result.base64);
  const output = execFileSync('java', ['--class-path', text('classpath.txt').trim(),
    new URL('GmInterop.java', import.meta.url).pathname, 'verify-rsa', fixtureDir.pathname], { encoding: 'utf8' });
  assert.match(output, /RSA GM0016 交叉解密验证通过/);
});

test('RSA 拒绝 GM0009、算法混用、证书错配和损坏的 CRT 参数', async () => {
  const rsaInputs = { signCert: text('rsa-sign.pem'), encCert: text('rsa-enc-2048.pem'),
    privateKey: text('rsa-enc-2048.key'), format: '0016' };
  assert.throws(() => convert({ ...rsaInputs, format: '0009' }), /GM0009.*SM2/);
  assert.throws(() => convert({ ...rsaInputs, signCert: text('sign.pem') }), /算法必须一致/);
  assert.throws(() => convert({ ...rsaInputs, privateKey: text('enc.key') }), /算法必须一致/);
  assert.throws(() => convert({ ...rsaInputs, privateKey: text('rsa-sign.key') }), /不匹配/);
  const { createPrivateKey } = await import('node:crypto');
  const jwk = createPrivateKey(rsaInputs.privateKey).export({ format: 'jwk' });
  for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
    const broken = Buffer.from(jwk[field], 'base64url');
    broken[broken.length - 1] ^= 2;
    const pem = createPrivateKey({ key: { ...jwk, [field]: broken.toString('base64url') }, format: 'jwk' })
      .export({ type: 'pkcs1', format: 'pem' }).toString();
    assert.throws(() => convert({ ...rsaInputs, privateKey: pem }), /RSA.*不一致/);
  }
  assert.notEqual(convert(rsaInputs).base64, convert(rsaInputs).base64);
  const encrypted = createPrivateKey(rsaInputs.privateKey).export({ type: 'pkcs8', format: 'pem',
    cipher: 'aes-256-cbc', passphrase: 'synthetic-test-only' }).toString();
  assert.throws(() => convert({ ...rsaInputs, privateKey: encrypted }), /加密 PEM/);
});
