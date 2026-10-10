import { readFile, writeFile } from 'node:fs/promises';
const root = new URL('./', import.meta.url);
const read = path => readFile(new URL(path, root), 'utf8');
const theme = await read('src/tool-theme.css');
const sources = { gm: 'tools/gm-key-converter/gm-key-converter.html', ukey: 'tools/admin-cert-sql.html', jasypt: 'tools/jasypt-decrypt.html' };
const documents = {};
for (const [id, path] of Object.entries(sources)) {
  documents[id] = (await read(path)).replace('</head>', `<style>${theme}</style></head>`);
}
// JSON 内的 < 必须转义，防止内嵌文档的 script 结束标签截断外层数据。
const payload = JSON.stringify(documents).replaceAll('<', '\\u003c');
const app = await read('src/app.js');
const html = (await read('src/index.html')).replace('__DOCUMENTS__', () => payload).replace('__APP__', () => app);
await writeFile(new URL('index.html', root), html);
console.log(`统一工具页已生成：${Buffer.byteLength(html)} 字节，三个工具完整内嵌。`);
