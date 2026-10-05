'use strict';

// 用户文本展示转义（XSS 修复）· 端到端 HTTP + 页端渲染自测（npm test）：
//   A. 接口契约保持（临时目录起服务）：
//      1) 上传文件名、细胞/视野名称、视野 id、报告标题、更正原因、比较标题
//         均可含 <img src=x onerror=alert(1)> 等片段：上传/保存/发布/更正/比较
//         接口字段与返回行为不变，读取回来的仍是录入原文；
//      2) 既有 CSV / ZIP 导出保留原文（导出内容不做 HTML 转义）；
//      3) 视野分析接口（覆盖核对/合并统计/网格/责任区/接触簇/覆盖变化核对）
//         对含片段的名称与 id 照常工作；错误提示原文返回（由页端负责转义）。
//   B. 页端展示转义（Node vm + 迷你 DOM 桩，加载真实 public/*.js）：
//      用 A 中真实接口数据驱动首页、报告列表、报告详情（当前有效 + 历史报告）、
//      草稿编辑器统计、比较工作台、覆盖变化核对页的全部渲染；
//      记录每一次 innerHTML 写入，断言：
//      - 任何写入都不含未转义的 <img/<svg/<script 片段（文本不会被解释为标签或事件）；
//      - 转义后的字面文本（&lt;img …&gt; 等）确实出现在页面中（内容完整可见）；
//      - 动态生成的 option 值等属性中的引号被转义；
//      - 选择、合并统计、覆盖核对、网格/责任区/接触簇分析、比较配对等渲染结果照常生成；
//      - textContent 通道（标题、文件名、输入框）保留原文供读取与编辑。

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const vm = require('vm');
const zlib = require('zlib');
const sharp = require('sharp');

const PORT = 8261;
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pm-xss-'));
const base = `http://localhost:${PORT}`;
let failures = 0;
function check(name, cond, extra) {
  if (cond) { console.log('ok -', name); }
  else { failures += 1; console.error('FAIL -', name, extra != null ? JSON.stringify(extra) : ''); }
}

// ---------- 恶意片段（录入内容；接口与导出必须保留原文，页面必须只显示字面文本） ----------
const P_IMG = '<img src=x onerror=alert(1)>';
const P_SVG = '<svg onload=alert(1)>';
const P_SCRIPT = '<script>alert(1)</script>';
const FILE_NAME = `xss${P_IMG}.png`;
const CELL1 = `细胞A${P_IMG}`;
const CELL2 = `细胞B${P_SVG}`;
const FIELD1 = `视野A${P_IMG}`;
const FIELD2 = `视野B${P_SVG}`;
const FIELD3_ID = `f3">${P_IMG}`; // 属性突破片段：动态 option 值必须转义引号
const FIELD3 = `视野C${P_SCRIPT}`;
const TITLE1 = `报告V1${P_IMG}`;
const TITLE2 = `报告V2${P_IMG}`;
const REASON = `更正原因${P_IMG}`;
const CMP_TITLE = `比较${P_IMG}`;
const GHOST = `不存在${P_IMG}`;

async function jget(p) {
  const res = await fetch(base + p);
  return { status: res.status, body: await res.json().catch(() => null) };
}
async function jsend(method, p, body) {
  const res = await fetch(base + p, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}
async function jtext(p) {
  const res = await fetch(base + p);
  return { status: res.status, text: await res.text() };
}
function upload(buffer, filename) {
  return new Promise((resolve, reject) => {
    const boundary = '----b' + Math.random().toString(16).slice(2);
    const head = Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="${filename}"\r\n` +
      'Content-Type: image/png\r\n\r\n');
    const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
    const req = require('http').request(base + '/api/images', {
      method: 'POST',
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': head.length + buffer.length + tail.length }
    }, (res) => {
      let d = ''; res.on('data', (c) => (d += c));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(d || '{}') }));
    });
    req.on('error', reject);
    req.write(head); req.write(buffer); req.write(tail); req.end();
  });
}
const pt = (x, y) => ({ x, y });

// 解析完整 ZIP（按中央目录）：[{name, data}]
function parseZip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('不是完整的 ZIP（缺少结尾目录）');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const entries = [];
  for (let i = 0; i < count; i++) {
    const method = buf.readUInt16LE(off + 10);
    const csize = buf.readUInt32LE(off + 20);
    const nlen = buf.readUInt16LE(off + 28);
    const elen = buf.readUInt16LE(off + 30);
    const clen = buf.readUInt16LE(off + 32);
    const lho = buf.readUInt32LE(off + 42);
    const name = buf.slice(off + 46, off + 46 + nlen).toString('utf8');
    const lnlen = buf.readUInt16LE(lho + 26);
    const lelen = buf.readUInt16LE(lho + 28);
    const start = lho + 30 + lnlen + lelen;
    const raw = buf.slice(start, start + csize);
    entries.push({ name, data: method === 8 ? zlib.inflateRawSync(raw) : raw });
    off += 46 + nlen + elen + clen;
  }
  return entries;
}

// ---------- B 部分：迷你 DOM 桩 ----------

const htmlWrites = [];   // 每一次 innerHTML 写入：{id, html}
const createdEls = [];   // document.createElement 创建的元素（供检查 textContent）

function makeEl(tag) {
  const el = {
    tagName: String(tag || 'div').toUpperCase(),
    children: [],
    style: {},
    dataset: {},
    _attrs: {},
    _innerHTML: '',
    _textContent: '',
    className: '',
    value: ''
  };
  const classes = new Set();
  el.classList = {
    add: (...cs) => cs.forEach((c) => classes.add(c)),
    remove: (...cs) => cs.forEach((c) => classes.delete(c)),
    toggle: (c, force) => {
      const want = force === undefined ? !classes.has(c) : !!force;
      if (want) classes.add(c); else classes.delete(c);
      return want;
    },
    contains: (c) => classes.has(c)
  };
  Object.defineProperty(el, 'innerHTML', {
    get() { return this._innerHTML; },
    set(v) {
      this._innerHTML = String(v);
      htmlWrites.push({ id: this.id || this.tagName, html: this._innerHTML });
    }
  });
  Object.defineProperty(el, 'textContent', {
    get() { return this._textContent; },
    set(v) { this._textContent = String(v); }
  });
  el.appendChild = (c) => { el.children.push(c); c.parentElement = el; return c; };
  el.remove = () => {};
  el.addEventListener = () => {};
  el.removeEventListener = () => {};
  el.setAttribute = (k, v) => { el._attrs[k] = String(v); };
  el.getAttribute = (k) => el._attrs[k];
  el.querySelector = () => makeEl('div');
  el.querySelectorAll = () => [];
  el.cloneNode = () => makeEl(el.tagName);
  el.click = () => {};
  el.focus = () => {};
  return el;
}

const byId = new Map();
const documentStub = {
  getElementById(id) {
    if (!byId.has(id)) { const e = makeEl('div'); e.id = id; byId.set(id, e); }
    return byId.get(id);
  },
  createElement(tag) { const e = makeEl(tag); createdEls.push(e); return e; },
  createElementNS(_ns, tag) { const e = makeEl(tag); createdEls.push(e); return e; },
  querySelectorAll: () => [],
  body: makeEl('body'),
  activeElement: null
};

// 加载真实前端脚本（与 index.html 同顺序；api.js 由测试桩替换以注入真实接口数据）
function loadFrontend() {
  const sandbox = {
    console,
    setTimeout, clearTimeout, setImmediate,
    crypto: require('crypto').webcrypto,
    location: { hash: '' },
    history: { replaceState() {} },
    alert() {}, confirm: () => true, prompt: () => null,
    URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} },
    Image: function () { return {}; },
    ResizeObserver: class { observe() {} disconnect() {} },
    addEventListener() {}, removeEventListener() {},
    document: documentStub
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  const files = [
    'public/escape.js',
    'public/geometry-client.js',
    'server/merge-stats.js', // 与浏览器一样按 UMD 脚本加载（/merge-stats.js）
    'public/canvas-view.js',
    'public/editor.js',
    'public/reports.js',
    'public/compare.js',
    'public/coverage-diff-view.js',
    'public/app.js'
  ];
  const src = files.map((f) =>
    `\n///// ${f} /////\n` + fs.readFileSync(path.join(__dirname, f), 'utf8')).join('\n');
  // app.js 不把 App 挂到 window；在同一脚本作用域内补一段导出，供测试驱动各视图
  const epilogue = '\n;window.__views = { App, Editor, Reports, Compare, CoverageDiffView };\n';
  vm.runInContext(src + epilogue, sandbox, { filename: 'frontend-bundle.js' });
  return sandbox;
}

async function flushMicrotasks() {
  for (let i = 0; i < 5; i++) await new Promise((s) => setImmediate(s));
}

// ---------- 主流程 ----------

async function main() {
  const srv = spawn(process.execPath, [path.join(__dirname, 'server', 'index.js')], {
    env: { ...process.env, PORT: String(PORT), DATA_DIR },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let started = false;
  srv.stdout.on('data', (d) => { if (String(d).includes('已启动')) started = true; });
  srv.stderr.on('data', (d) => process.stderr.write(d));
  for (let i = 0; i < 50 && !started; i++) await new Promise((r) => setTimeout(r, 100));
  if (!started) throw new Error('server did not start');

  const ctx = {};
  try {
    // ---------- A0：造数据（全部用户文本都含 HTML 片段） ----------
    const png = await sharp({ create: { width: 300, height: 300, channels: 3, background: '#ffffff' } })
      .png().toBuffer();
    const up = await upload(png, FILE_NAME);
    check('A0 含片段文件名上传成功（201）', up.status === 201, up);
    const imgId = up.body.id;

    let r = await jsend('PUT', `/api/images/${imgId}/calibration`, {
      version: 1, p1: pt(0, 0), p2: pt(100, 0), distanceUm: 100
    });
    r = await jsend('PUT', `/api/images/${imgId}/contours`, {
      version: r.body.version,
      cells: [
        { id: 'c1', name: CELL1, outer: [pt(20, 20), pt(60, 20), pt(60, 60), pt(20, 60)], holes: [] },
        { id: 'c2', name: CELL2, outer: [pt(65, 20), pt(105, 20), pt(105, 60), pt(65, 60)], holes: [] }
      ]
    });
    check('A0 含片段细胞名保存成功', r.status === 200, r.body);
    r = await jsend('PUT', `/api/images/${imgId}/fields`, {
      version: r.body.version,
      fields: [
        { id: 'f1', name: FIELD1, outer: [pt(0, 0), pt(290, 0), pt(290, 290), pt(0, 290)], holes: [] },
        { id: 'f2', name: FIELD2, outer: [pt(10, 10), pt(100, 10), pt(100, 100), pt(10, 100)], holes: [] },
        { id: FIELD3_ID, name: FIELD3, outer: [pt(150, 150), pt(200, 150), pt(200, 200), pt(150, 200)], holes: [] }
      ]
    });
    check('A0 含片段视野名/视野 id 保存成功', r.status === 200, r.body);

    let p = await jsend('POST', `/api/images/${imgId}/publish`, { version: r.body.version, title: TITLE1 });
    check('A0 含片段标题发布成功（201）', p.status === 201, p.body);
    const report1 = p.body.report;

    // 改动草稿后发起更正（含片段的更正原因与新标题）
    const cur = await jget(`/api/images/${imgId}`);
    r = await jsend('PUT', `/api/images/${imgId}/contours`, {
      version: cur.body.version,
      cells: cur.body.cells.map((c) => ({ id: c.id, name: c.name, outer: c.outer, holes: c.holes }))
    });
    p = await jsend('POST', `/api/reports/${report1.id}/correct`, {
      reason: REASON, draftVersion: r.body.version, expectedTipId: report1.id, title: TITLE2
    });
    check('A0 含片段更正原因/标题更正成功（201）', p.status === 201, p.body);
    const report2 = p.body.report;

    const cmpRes = await jsend('POST', '/api/comparisons', {
      baselineReportId: report1.id, retestReportId: report2.id,
      title: CMP_TITLE,
      pairs: [{ baselineCellKey: 'c1', retestCellKey: 'c1' }]
    });
    check('A0 含片段标题的比较记录创建成功（201）', cmpRes.status === 201, cmpRes.body);

    // ---------- A1：读取接口原样返回录入内容（契约不变） ----------
    const draft = (await jget(`/api/images/${imgId}`)).body;
    check('A1 草稿读取保留文件名原文', draft.filename === FILE_NAME, draft.filename);
    check('A1 草稿读取保留细胞名原文',
      draft.cells[0].name === CELL1 && draft.cells[1].name === CELL2);
    check('A1 草稿读取保留视野名与视野 id 原文',
      draft.fields[0].name === FIELD1 && draft.fields[1].name === FIELD2 &&
      draft.fields[2].name === FIELD3 && draft.fields[2].id === FIELD3_ID);

    const rep2 = (await jget(`/api/reports/${report2.id}`)).body;
    const rep1 = (await jget(`/api/reports/${report1.id}`)).body;
    check('A1 报告读取保留标题/文件名/细胞名/视野名原文',
      rep2.title === TITLE2 && rep2.filename === FILE_NAME &&
      rep2.cells[0].name === CELL1 && rep2.fields[0].name === FIELD1);
    check('A1 历史报告按原标识读取且保留原文',
      rep1.title === TITLE1 && rep1.filename === FILE_NAME && rep1.cells[1].name === CELL2);
    check('A1 更正原因原文保留', rep2.correctionReason === REASON, rep2.correctionReason);

    const chains = (await jget('/api/report-chains')).body.chains;
    const chain = chains.find((c) => c.tipId === report2.id);
    check('A1 更正链列表保留最近更正原因原文', chain && chain.reason === REASON, chain && chain.reason);
    check('A1 更正链历史保留旧标题原文', chain && chain.history[0].title === TITLE1);
    const trace1 = (await jget(`/api/reports/${report1.id}/trace`)).body;
    const trace2 = (await jget(`/api/reports/${report2.id}/trace`)).body;
    check('A1 追溯视图保留各版标题原文',
      trace2.members[0].title === TITLE1 && trace2.members[1].title === TITLE2);

    const cmpView = (await jget(`/api/comparisons/${cmpRes.body.id}`)).body;
    check('A1 比较记录读取保留标题原文', cmpView.title === CMP_TITLE, cmpView.title);
    const cmpList = (await jget('/api/comparisons')).body;
    check('A1 比较列表保留标题原文', cmpList[0] && cmpList[0].title === CMP_TITLE);

    // ---------- A2：CSV / ZIP 导出保留原文（既有导出行为不变） ----------
    const csv = await jtext(`/api/reports/${report2.id}/csv`);
    check('A2 测量 CSV 保留细胞名与标题原文',
      csv.text.includes(CELL1) && csv.text.includes(TITLE2) && csv.text.includes(FILE_NAME));
    const fcsv = await jtext(`/api/reports/${report2.id}/field-csv`);
    check('A2 视野统计 CSV 保留视野名原文', fcsv.text.includes(FIELD1) && fcsv.text.includes(FIELD2));
    const ccsv = await jtext(`/api/comparisons/${cmpRes.body.id}/csv`);
    check('A2 比较 CSV 保留标题与细胞名原文',
      ccsv.text.includes(CMP_TITLE) && ccsv.text.includes(CELL1) && ccsv.text.includes(CELL2));
    {
      const res = await fetch(`${base}/api/reports/export`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: [report1.id, report2.id], format: 'zip' })
      });
      check('A2 ZIP 导出仍为 200', res.status === 200);
      const entries = parseZip(Buffer.from(await res.arrayBuffer()));
      check('A2 ZIP 条目数量不变（2 报告 × 2 + 汇总）', entries.length === 5,
        entries.map((e) => e.name));
      const csvEntry = entries.find((e) => e.name.endsWith('_测量.csv') &&
        e.data.toString('utf8').includes(CELL1));
      check('A2 ZIP 内测量 CSV 保留细胞名原文', !!csvEntry);
    }

    // ---------- A3：分析接口对含片段的名称/id 照常工作；错误提示原文返回 ----------
    const cov = await jsend('POST', `/api/reports/${report2.id}/field-coverage`, { fieldId: FIELD1 });
    check('A3 按含片段视野名核对覆盖 → 200 且按名称匹配',
      cov.status === 200 && cov.body.matchedBy === 'name' && cov.body.coverage.fieldName === FIELD1,
      cov.body);
    const merge = await jsend('POST', `/api/reports/${report2.id}/field-merge`, { fieldIds: ['f1', 'f2'] });
    check('A3 合并统计返回视野名原文',
      merge.status === 200 && merge.body.stats.fieldNames[0] === FIELD1, merge.body);
    const mergeBadId = await jsend('POST', `/api/reports/${report2.id}/field-merge`,
      { fieldIds: ['f2', FIELD3_ID] });
    check('A3 含片段视野 id 照常参与合并统计',
      mergeBadId.status === 200 && mergeBadId.body.stats.fieldCount === 2, mergeBadId.body);
    const grid = await jsend('POST', `/api/reports/${report2.id}/field-grid`,
      { fieldId: 'f1', rows: 2, cols: 2 });
    check('A3 网格密度分析 200', grid.status === 200 && grid.body.grid.fieldName === FIELD1, grid.body);
    const zones = await jsend('POST', `/api/reports/${report2.id}/field-zones`, { fieldId: 'f1' });
    check('A3 责任区分析 200 且计入细胞名原文',
      zones.status === 200 && zones.body.zones.zones[0].name === CELL1, zones.body);
    const contacts = await jsend('POST', `/api/reports/${report2.id}/contacts`, { thresholdUm: 5 });
    check('A3 接触簇分析 200 且细胞名原文',
      contacts.status === 200 && contacts.body.cells[0].name === CELL1, contacts.body);
    const diff = await jsend('POST', '/api/reports/field-coverage-diff', {
      baselineReportId: report1.id, retestReportId: report2.id, fieldId: 'f1'
    });
    check('A3 覆盖变化核对 200 且视野名原文',
      diff.status === 200 && diff.body.diff.fieldName === FIELD1, diff.body);
    const ghost = await jsend('POST', `/api/reports/${report2.id}/field-coverage`, { fieldId: GHOST });
    check('A3 错误提示保留用户输入原文（由页端负责转义）',
      ghost.status === 400 && ghost.body.error.includes(GHOST), ghost.body);

    // ---------- B：页端渲染转义（真实前端脚本 + 真实接口数据） ----------
    Object.assign(ctx, {
      draft, rep1, rep2, chains, trace1, trace2, cmpView, cmpList,
      coverage: cov.body, grid: grid.body, zones: zones.body,
      contacts: contacts.body, diff: diff.body, ghostError: ghost.body.error
    });
    await testFrontend(ctx);
  } finally {
    srv.kill();
    fs.rmSync(DATA_DIR, { recursive: true, force: true });
  }

  if (failures) { console.error(`\n${failures} 项失败`); process.exit(1); }
  console.log('\n全部「用户文本展示转义」自测通过 ✔');
}

async function testFrontend(d) {
  const sandbox = loadFrontend();
  const { Editor, Reports, Compare, CoverageDiffView, App } = sandbox.__views;

  // API 桩：返回 A 部分从真实服务取到的数据（含全部恶意片段）
  sandbox.API = {
    listImages: async () => [d.draft],
    listReportChains: async () => ({ chains: d.chains }),
    getReport: async (id) => (id === d.rep1.id ? d.rep1 : d.rep2),
    traceReport: async (id) => (id === d.rep1.id ? d.trace1 : d.trace2),
    getImage: async () => d.draft,
    listComparisons: async () => d.cmpList,
    getComparison: async () => d.cmpView,
    reportFieldCoverage: async () => d.coverage,
    reportFieldGrid: async () => d.grid,
    reportFieldZones: async () => d.zones,
    reportContacts: async () => d.contacts,
    reportFieldCoverageDiff: async () => d.diff,
    exportCsvUrl: (id) => `/api/reports/${id}/csv`,
    exportFieldCsvUrl: (id) => `/api/reports/${id}/field-csv`,
    exportPngUrl: (id) => `/api/reports/${id}/png`,
    comparisonCsvUrl: (id) => `/api/comparisons/${id}/csv`
  };

  // 只读画布桩（避免构造真实 CanvasView）
  Reports.detailView = {
    readOnly: false, cb: {},
    bindState() {}, setTool() {}, render() {}, destroy() {},
    async loadImage() {}
  };

  // 1) 首页图片列表（文件名）
  await App.renderHome();
  // 2) 报告列表（标题/文件名/更正原因/历史）
  await Reports.showList();
  // 3) 当前有效报告详情 + 各分析面板
  await Reports.showDetail(d.rep2.id);
  await flushMicrotasks(); // trace/draft 异步回填
  check('B 报告详情标题经 textContent 保留原文', documentStub.getElementById('rp-title')._textContent === TITLE2,
    documentStub.getElementById('rp-title')._textContent);
  // 报告内合并统计（勾选全部 3 个视野，含恶意 id）
  Reports.mergeSelected = d.rep2.fields.map((f) => f.id);
  Reports.renderReportMerge(d.rep2);
  // 覆盖核对（按恶意视野名）+ 错误提示路径（含片段的 400 原文）
  documentStub.getElementById('rp-coverage-field-id').value = FIELD1;
  await Reports.runCoverageQuery();
  sandbox.API.reportFieldCoverage = async () => {
    const e = new Error(d.ghostError); e.status = 400; throw e;
  };
  documentStub.getElementById('rp-coverage-field-id').value = GHOST;
  await Reports.runCoverageQuery();
  // 网格密度 / 责任区 / 接触簇
  documentStub.getElementById('rp-grid-field-id').value = 'f1';
  documentStub.getElementById('rp-grid-rows').value = '2';
  documentStub.getElementById('rp-grid-cols').value = '2';
  await Reports.runGridAnalysis();
  documentStub.getElementById('rp-zones-field-id').value = 'f1';
  await Reports.runZonesAnalysis();
  documentStub.getElementById('rp-contact-threshold').value = '5';
  await Reports.runContactAnalysis();
  // 4) 历史报告详情（被更正取代的旧版，按原标识查看）
  await Reports.showDetail(d.rep1.id);
  await flushMicrotasks();
  check('B 历史报告标题经 textContent 保留原文', documentStub.getElementById('rp-title')._textContent === TITLE1,
    documentStub.getElementById('rp-title')._textContent);

  // 5) 草稿编辑器统计（测量表 / 视野密度统计 / 合并统计 / 覆盖核对 / datalist）
  Editor.img = d.draft;
  Editor.cells = JSON.parse(JSON.stringify(d.draft.cells));
  Editor.fields = JSON.parse(JSON.stringify(d.draft.fields));
  Editor.dirty = true;
  Editor.fieldsDirty = true;
  Editor.activeCellId = d.draft.cells[0].id;
  Editor.activeFieldId = d.draft.fields[0].id;
  Editor.mergeSelected = d.draft.fields.map((f) => f.id);
  Editor.coverageQuery = FIELD1;
  Editor.coverageResult = null;
  Editor.migrate = { reportId: null, report: null, sourceImg: null,
    sourcePoints: [], targetPoints: [], preview: null };
  Editor.preview = null;
  Editor.renderSidebar();
  check('B 编辑器标题经 textContent 保留文件名原文', documentStub.getElementById('ed-title')._textContent === FILE_NAME,
    documentStub.getElementById('ed-title')._textContent);
  // 迁移预览结果（label/error 含片段）
  Editor.migrate.preview = {
    ok: false, okCount: 0, failCount: 1, target: { version: 3 },
    cells: [{ label: `细胞「${P_IMG}」`, ok: false, error: `外轮廓越界${P_IMG}`,
      areaUm2: null, perimeterUm: null }]
  };
  Editor.renderMigratePanel();
  // 修订时间线（说明含片段）与修订预览（快照内名称含片段）
  Editor.revisions = [{
    id: 'rev1', seq: 2, type: 'contours', typeLabel: '轮廓保存',
    note: `保存${P_IMG}`, draftVersion: 2, calibrated: true,
    cellCount: 2, fieldCount: 3, isRestore: false, createdAt: '2026-01-01 00:00:00'
  }];
  Editor.renderRevisionList();
  Editor.preview = {
    rev: {
      id: 'rev1', seq: 2, typeLabel: '轮廓保存', draftVersion: 2,
      calib: d.draft.calib, cells: d.draft.cells, fields: d.draft.fields,
      fieldStats: d.draft.fieldStats
    },
    readVersion: 1
  };
  Editor.renderRevisionPreview();
  // 旧草稿遗留的重复视野 id 冲突横幅（id/名称含片段）
  Editor.fields = [
    { id: FIELD3_ID, name: FIELD3, outer: [pt(150, 150), pt(200, 150), pt(200, 200), pt(150, 200)], holes: [] },
    { id: FIELD3_ID, name: FIELD1, outer: [pt(0, 0), pt(290, 0), pt(290, 290), pt(0, 290)], holes: [] }
  ];
  Editor.renderFieldConflictBanner();

  // 6) 比较工作台（固定两侧报告 + 未配对细胞 chips + 配对表）
  await Compare.showList();
  await Compare.openEdit(d.cmpView.id);
  check('B 比较标题输入框保留原文供编辑', documentStub.getElementById('cmp-title').value === CMP_TITLE,
    documentStub.getElementById('cmp-title').value);

  // 7) 覆盖变化核对页（基线/复测标题、基线视野名）
  CoverageDiffView.reports = [d.rep1, d.rep2];
  CoverageDiffView.render(d.diff);

  // ---------- 汇总断言 ----------
  check('B 渲染产生了大量 innerHTML 写入（各视图均已执行）', htmlWrites.length > 60,
    { writes: htmlWrites.length });
  const joined = htmlWrites.map((w) => w.html).join('\n');
  const lowered = joined.toLowerCase();
  check('B 任何 innerHTML 写入都不含未转义的 <img 标签', !lowered.includes('<img'));
  check('B 任何 innerHTML 写入都不含未转义的 <svg 标签', !lowered.includes('<svg'));
  check('B 任何 innerHTML 写入都不含未转义的 <script 标签', !lowered.includes('<script'));
  check('B img 片段按字面文本显示（&lt;img…&gt;）',
    joined.includes(`&lt;img src=x onerror=alert(1)&gt;`));
  check('B svg 片段按字面文本显示（&lt;svg…&gt;）',
    joined.includes(`&lt;svg onload=alert(1)&gt;`));
  check('B script 片段按字面文本显示（&lt;script&gt;…）',
    joined.includes(`&lt;script&gt;alert(1)&lt;/script&gt;`));
  check('B 动态 option 值中的引号被转义（属性不被突破）',
    joined.includes(`f3&quot;&gt;&lt;img src=x onerror=alert(1)&gt;`));
  check('B 错误提示中的用户输入按字面文本显示',
    joined.includes(`视野标识不存在：&lt;img`) || joined.includes(`&lt;img src=x onerror=alert(1)&gt;（不属于`));

  // 原有选择、比较、分析与展示操作照常生成结果
  check('B 报告列表渲染（更正链 ×2）', joined.includes('更正链 ×2'));
  check('B 草稿视野密度统计表渲染', joined.includes('计入细胞净面积总和'));
  check('B 草稿/报告合并统计结果渲染', joined.includes('合并视野'));
  check('B 覆盖核对结果渲染（覆盖率）', joined.includes('覆盖率'));
  check('B 网格密度结果渲染', joined.includes('密度 个/mm²'));
  check('B 责任区结果渲染', joined.includes('责任区面积'));
  check('B 接触簇结果渲染', joined.includes('连通簇'));
  check('B 比较工作台渲染（配对比较结果）', joined.includes('配对比较结果'));
  check('B 覆盖变化核对渲染（四类合计）', joined.includes('四类合计'));
  check('B 首页文件名按字面文本创建（textContent 通道）',
    createdEls.some((e) => e._textContent === FILE_NAME));
}

main().catch((e) => { console.error(e); process.exit(1); });
