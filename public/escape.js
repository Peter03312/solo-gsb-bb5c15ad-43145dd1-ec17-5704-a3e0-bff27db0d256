'use strict';

// 用户文本展示转义（全页共用一个实现）。
//
// 上传文件名、细胞/视野名称、报告/比较标题、更正原因、视野与细胞 id 等都是
// 用户可录入的文本：读取、编辑与 CSV/ZIP 导出一律保留原文，但任何把文本拼进
// 页面 HTML 的地方（innerHTML 模板、动态生成的 option 值、属性、错误提示）
// 都必须先经本函数转义，使页面只按字面文本显示，绝不把文本解释为标签或事件。
// 服务端只返回 JSON、不渲染 HTML，因此转义统一在页端展示层完成。
function escHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

window.escHtml = escHtml;
