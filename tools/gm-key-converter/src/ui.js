import { convert, MAX_INPUT_BYTES, parseCertificate, parsePrivateKey } from './core.js';

const byId = (id) => document.getElementById(id);
const fields = ['sign', 'enc', 'key'];
const generations = { sign: 0, enc: 0, key: 0 };
let result = null;
let inputRevision = 0;
let pendingReads = 0;
let busy = false;
const selectedFormat = () => document.querySelector('input[name="format"]:checked').value;

function message(text, error = false) {
  byId('message').textContent = text;
  byId('message').classList.toggle('error', error);
  byId('message').hidden = !text;
}

function resetResult() {
  inputRevision++;
  result = null;
  byId('output').value = '';
  byId('copy').disabled = true;
  byId('download').disabled = true;
  byId('result-size').textContent = '— 字节 / — 字符';
  byId('result-status').textContent = '等待生成';
  byId('result-status').classList.remove('success');
  message('');
}

function syncConvertButton() {
  byId('convert').disabled = pendingReads > 0 || busy;
}

function markField(field, name) {
  const element = byId(field + '-name');
  element.textContent = name;
  element.classList.toggle('ready', !!byId(field + '-text').value.trim());
  document.querySelector(`[data-field="${field}"]`).classList.remove('has-error');
}

/** DER 文件转成 PEM 展示，让文件选择与粘贴始终使用同一份可见输入。 */
function certificatePem(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  return '-----BEGIN CERTIFICATE-----\n' + btoa(binary).match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----';
}

async function loadFile(field, file) {
  const generation = ++generations[field];
  resetResult();
  byId(field + '-text').value = '';
  markField(field, '正在读取…');
  pendingReads++;
  syncConvertButton();
  try {
    if (!file || file.size === 0) throw new Error('文件为空，请重新选择。');
    if (file.size > MAX_INPUT_BYTES) throw new Error('文件超过 256 KiB，请选择单份证书或私钥。');
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (generation !== generations[field]) return;
    let text = new TextDecoder().decode(bytes).trim();
    if (field === 'key') {
      parsePrivateKey(text);
    } else {
      parseCertificate(bytes);
      if (!text.startsWith('-----BEGIN')) text = certificatePem(bytes);
    }
    byId(field + '-text').value = text;
    markField(field, file.name);
  } catch (error) {
    if (generation !== generations[field]) return;
    markField(field, '读取失败，请重新选择');
    document.querySelector(`[data-field="${field}"]`).classList.add('has-error');
    const title = { sign: '签名证书', enc: '加密证书', key: '加密私钥' }[field];
    message(title + '：' + error.message, true);
  } finally {
    pendingReads--;
    byId(field + '-file').value = '';
    syncConvertButton();
  }
}

for (const field of fields) {
  const area = byId(field + '-text');
  const fileInput = byId(field + '-file');
  document.querySelector(`[data-pick="${field}"]`).addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => { if (fileInput.files[0]) loadFile(field, fileInput.files[0]); });
  area.addEventListener('input', () => {
    generations[field]++;
    resetResult();
    markField(field, area.value.trim() ? '已输入 PEM 文本' : '尚未选择文件');
  });
  const card = document.querySelector(`[data-field="${field}"]`);
  card.addEventListener('dragover', (event) => {
    if (event.dataTransfer.types.includes('Files')) { event.preventDefault(); card.classList.add('dragging'); }
  });
  card.addEventListener('dragleave', (event) => { if (!card.contains(event.relatedTarget)) card.classList.remove('dragging'); });
  card.addEventListener('drop', (event) => {
    card.classList.remove('dragging');
    if (!event.dataTransfer.types.includes('Files')) return;
    event.preventDefault();
    if (event.dataTransfer.files.length !== 1) {
      resetResult();
      message('每个输入框只能接收一个文件。', true);
      return;
    }
    loadFile(field, event.dataTransfer.files[0]);
  });
}

// 防止把文件拖到卡片之外时浏览器跳转，丢失当前输入。
document.addEventListener('dragover', (event) => { if (event.dataTransfer.types.includes('Files')) event.preventDefault(); });
document.addEventListener('drop', (event) => { if (event.dataTransfer.types.includes('Files')) event.preventDefault(); });

for (const radio of document.querySelectorAll('input[name="format"]')) {
  radio.addEventListener('change', () => {
    resetResult();
    const is0016 = selectedFormat() === '0016';
    byId('result-format').textContent = 'GM' + selectedFormat();
    byId('format-description').textContent = is0016 ? '智能密码钥匙密钥保护结构' : 'SM2 加密密钥对保护结构';
    byId('format-tag').textContent = is0016 ? '小端序 / LE' : 'ASN.1 / DER';
  });
}

byId('convert').addEventListener('click', async () => {
  resetResult();
  for (const field of fields) {
    if (!byId(field + '-text').value.trim()) {
      message('请先提供签名证书、加密证书和加密私钥。', true);
      byId(field + '-text').focus();
      return;
    }
  }
  busy = true;
  syncConvertButton();
  const revision = inputRevision;
  byId('result-status').textContent = '正在校验与转换…';
  try {
    // 让浏览器先绘制进度，随后在当前页面内完成计算。
    await new Promise((resolve) => setTimeout(resolve, 30));
    if (revision !== inputRevision) return;
    result = convert({ signCert: byId('sign-text').value, encCert: byId('enc-text').value,
      privateKey: byId('key-text').value, format: selectedFormat() });
    byId('output').value = result.base64;
    byId('copy').disabled = false;
    byId('download').disabled = false;
    byId('result-status').textContent = '已生成';
    byId('result-status').classList.add('success');
    byId('result-size').textContent = `${result.byteLength} 字节 / ${result.base64.length} 字符`;
    message(`GM${result.format} 已生成，加密证书与私钥匹配。`);
  } catch (error) {
    result = null;
    byId('result-status').textContent = '转换失败';
    message(error.message || '转换失败，请检查输入文件。', true);
  } finally {
    busy = false;
    syncConvertButton();
  }
});

byId('copy').addEventListener('click', async () => {
  if (!result) return;
  const revision = inputRevision;
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard API 不可用');
    await navigator.clipboard.writeText(result.base64);
    if (revision === inputRevision) message('Base64 已复制。');
  } catch {
    if (revision !== inputRevision || !result) return;
    const output = byId('output');
    output.focus();
    output.select();
    const copied = document.execCommand('copy');
    message(copied ? 'Base64 已复制。' : '浏览器未允许自动复制，已选中结果，请按 Ctrl+C 或 ⌘C 复制。');
  }
});

byId('download').addEventListener('click', () => {
  if (!result) return;
  const url = URL.createObjectURL(new Blob([result.base64], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `GM${result.format}_enveloped_key.key`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

function clearInputs() {
  for (const field of fields) {
    generations[field]++;
    byId(field + '-text').value = '';
    byId(field + '-file').value = '';
    markField(field, '尚未选择文件');
  }
  resetResult();
}

byId('clear').addEventListener('click', () => { clearInputs(); message('已清空输入与结果。'); });
window.addEventListener('pagehide', clearInputs);
clearInputs();
