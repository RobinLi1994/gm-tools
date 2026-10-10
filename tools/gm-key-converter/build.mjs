import { build } from 'esbuild';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const root = new URL('./', import.meta.url);
const result = await build({
  entryPoints: [new URL('src/ui.js', root).pathname],
  bundle: true, write: false, minify: true, platform: 'browser', format: 'iife',
  target: ['es2020'], legalComments: 'inline',
  plugins: [{
    name: 'browser-crypto-only',
    setup(builder) {
      // 依赖保留了 Node 兼容分支；构建时统一绑定浏览器 CSPRNG，杜绝运行时加载。
      builder.onResolve({ filter: /^(node:)?crypto$/ }, () => ({ path: 'browser-crypto', namespace: 'local-crypto' }));
      builder.onLoad({ filter: /.*/, namespace: 'local-crypto' }, () => ({ contents: 'export const webcrypto = globalThis.crypto;', loader: 'js' }));
    },
  }],
});
const bundle = result.outputFiles[0].text.replace(/<\/script/gi, '<\\/script');
const scriptHash = createHash('sha256').update(bundle).digest('base64');
const packages = ['sm-crypto-v2', '@noble/curves', '@noble/hashes', '@noble/ciphers'];
let licenses = '';
for (const name of packages) {
  const path = new URL(`node_modules/${name}/`, root);
  const pkg = JSON.parse(await readFile(new URL('package.json', path), 'utf8'));
  const license = await readFile(new URL(name === 'sm-crypto-v2' ? 'LICENCE_MIT' : 'LICENSE', path), 'utf8');
  licenses += `${name} ${pkg.version}\n${license}\n\n`;
}
const escapeHtml = (text) => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const template = await readFile(new URL('src/page.html', root), 'utf8');
const html = template.replace('__SCRIPT_HASH__', scriptHash).replace('__LICENSES__', escapeHtml(licenses)).replace('__BUNDLE__', () => bundle);
await writeFile(new URL('gm-key-converter.html', root), html);
console.log(`离线 HTML 已生成：${Buffer.byteLength(html)} 字节（全部依赖内嵌）`);
