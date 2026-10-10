// 每个工具独立文档，避免旧工具的同名字段、全局函数和样式互相影响。
const documents = JSON.parse(document.getElementById('tool-documents').textContent);
const tabs = [...document.querySelectorAll('[role="tab"]')];
const frames = new Map();
let active = 'gm';

function mountTool(id) {
  if (frames.has(id)) return;
  const frame = document.createElement('iframe');
  frame.id = 'tool-' + id;
  frame.title = document.getElementById('tab-' + id).textContent.replace(/^0[123]/, '').trim();
  // srcdoc 只载入随构建内嵌的可信源码，不接受任何用户输入。
  frame.srcdoc = documents[id];
  frame.addEventListener('load', () => {
    const doc = frame.contentDocument;
    if (!doc || frames.get(id)?.frame !== frame) return;
    const resize = () => {
      if (frame.isConnected && !document.getElementById('panel-' + id).hidden) {
        frame.style.height = Math.max(300, Math.ceil(doc.body.getBoundingClientRect().height) + 24) + 'px';
      }
    };
    const observer = new ResizeObserver(resize);
    observer.observe(doc.body);
    frames.get(id).observer = observer;
    frames.get(id).resize = resize;
    resize();
  });
  frames.set(id, { frame });
  document.getElementById('mount-' + id).append(frame);
}

function selectTool(id, focus = false) {
  active = id;
  for (const tab of tabs) {
    const selected = tab.dataset.tool === id;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    document.getElementById(tab.getAttribute('aria-controls')).hidden = !selected;
    if (selected && focus) tab.focus();
  }
  mountTool(id);
  frames.get(id).resize?.();
}

for (const [index, tab] of tabs.entries()) {
  tab.addEventListener('click', () => selectTool(tab.dataset.tool));
  tab.addEventListener('keydown', event => {
    let next;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length - 1;
    if (next !== undefined) { event.preventDefault(); selectTool(tabs[next].dataset.tool, true); }
  });
}

function disposeTools() {
  // 销毁整个子文档，移除内存状态与事件闭包；旧异步回调不能回填到新页面。
  for (const { frame, observer } of frames.values()) {
    observer?.disconnect();
    frame.remove();
  }
  frames.clear();
}

document.getElementById('clear-all').addEventListener('click', () => {
  disposeTools();
  mountTool(active);
  document.getElementById('app-status').textContent = '所有工具的输入与结果已清空。';
});
window.addEventListener('pagehide', disposeTools);
window.addEventListener('pageshow', () => selectTool(active));

// 下载干净构建文件，而非当前 DOM，避免把输入、密码或结果写入离线文件。
const sourceHtml = '<!doctype html>\n' + document.documentElement.outerHTML;
const downloadUrl = URL.createObjectURL(new Blob([sourceHtml], { type: 'text/html;charset=utf-8' }));
document.getElementById('download-page').href = downloadUrl;
selectTool(active);
