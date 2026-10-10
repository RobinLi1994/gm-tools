async (page) => {
  const base = decodeURIComponent(new URL('.', page.url()).pathname);
  const requests = [];
  const errors = [];
  page.on('request', (request) => { if (/^https?:/.test(request.url())) requests.push(request.url()); });
  page.on('pageerror', (error) => errors.push(error.message));
  await page.context().setOffline(true);
  await page.reload();
  const requireValue = (condition, text) => { if (!condition) throw new Error(text); };
  const choose = async (index, file) => {
    await page.locator('input[type="file"]').nth(index).setInputFiles(base + 'build/fixtures/' + file);
    await page.waitForFunction(() => !document.getElementById('convert').disabled);
  };
  const generate = async () => {
    await page.getByRole('button', { name: '生成密钥文件', exact: true }).click();
    await page.waitForFunction(() => document.getElementById('result-status').textContent === '已生成');
    return page.getByRole('textbox', { name: 'Base64 转换结果', exact: true }).inputValue();
  };

  await page.getByRole('button', { name: '生成密钥文件', exact: true }).click();
  requireValue((await page.getByRole('status').textContent()).includes('请先提供'), '空输入缺少提示');
  await choose(0, 'sign.pem');
  await choose(1, 'enc.der');
  await choose(2, 'enc.key');
  const signPem = await page.getByRole('textbox', { name: '签名证书', exact: true }).inputValue();
  const encPem = await page.getByRole('textbox', { name: '加密证书', exact: true }).inputValue();
  const keyPem = await page.getByRole('textbox', { name: '加密私钥', exact: true }).inputValue();
  const result0016 = await generate();
  requireValue(result0016.length === 520, 'GM0016 Base64 长度错误');
  await page.getByRole('button', { name: '复制 Base64', exact: true }).click();
  await page.waitForFunction(() => document.getElementById('message').textContent.includes('已复制'));
  for (const format of ['0016', '0009']) {
    if (format === '0009') {
      await page.getByRole('radio', { name: 'GM0009', exact: true }).check();
      requireValue(await page.getByRole('button', { name: '下载 .key ↓', exact: true }).isDisabled(), '切换格式没有清除旧结果');
      await generate();
    }
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: '下载 .key ↓', exact: true }).click();
    const file = await download;
    requireValue(file.suggestedFilename() === `GM${format}_enveloped_key.key`, '下载文件名错误');
    await file.saveAs(base + `build/fixtures/output-${format}.key`);
  }
  await choose(2, 'enc-sec1.key');
  const sec1Pem = await page.getByRole('textbox', { name: '加密私钥', exact: true }).inputValue();
  await page.getByRole('button', { name: '清空全部', exact: true }).click();
  for (const label of ['签名证书', '加密证书', '加密私钥', 'Base64 转换结果']) {
    requireValue(await page.getByRole('textbox', { name: label, exact: true }).inputValue() === '', '清空后仍有内容');
  }
  await page.getByRole('textbox', { name: '签名证书', exact: true }).fill(signPem);
  await page.getByRole('textbox', { name: '加密证书', exact: true }).fill(encPem);
  await page.getByRole('textbox', { name: '加密私钥', exact: true }).fill(sec1Pem);
  await generate();
  await page.getByRole('textbox', { name: '加密私钥', exact: true }).fill(keyPem + '\n');
  requireValue(await page.getByRole('button', { name: '复制 Base64', exact: true }).isDisabled(), '输入变化没有使旧结果失效');

  // 用合成 PEM 构造真实 DataTransfer，验证文件拖拽分支。
  await page.getByRole('button', { name: '清空全部', exact: true }).click();
  const dataTransfer = await page.evaluateHandle((text) => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([text], 'drag-sign.pem', { type: 'text/plain' }));
    return transfer;
  }, signPem);
  await page.getByRole('heading', { name: '签名证书', exact: true }).dispatchEvent('drop', { dataTransfer });
  await page.waitForFunction(() => document.getElementById('sign-name').textContent === 'drag-sign.pem');
  requireValue(await page.getByRole('textbox', { name: '签名证书', exact: true }).inputValue() === signPem.trim(), '拖拽证书内容不一致');
  await dataTransfer.dispose();
  await page.getByRole('textbox', { name: '加密证书', exact: true }).fill(encPem);
  await page.getByRole('textbox', { name: '加密私钥', exact: true }).fill(keyPem);
  await page.getByRole('radio', { name: 'GM0016', exact: true }).check();
  await generate();
  requireValue(await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0), '发现浏览器持久化数据');
  await page.getByRole('button', { name: '清空全部', exact: true }).click();
  await page.screenshot({ path: base + 'build/browser/desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  requireValue(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), '移动端出现横向溢出');
  await page.screenshot({ path: base + 'build/browser/mobile.png', fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1050 });
  requireValue(requests.length === 0, '发现网络请求');
  requireValue(errors.length === 0, '浏览器脚本错误：' + errors.join('; '));
  return '浏览器检查通过：离线 file://、PEM/DER 文件选择、SEC1 粘贴、文件拖拽、GM0016/GM0009 转换、复制、两份下载、旧结果失效、清空、无持久化、移动端布局、零 HTTP 请求。';
}
