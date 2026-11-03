"use strict";
const $ = (s, el = document) => el.querySelector(s);
const view = $("#view");
const TYPE_LABEL = {ip: "IP", domain: "域名", url: "URL", file_hash: "文件哈希", md5: "MD5", sha1: "SHA1", sha256: "SHA256", keyword: "关键词"};
const KIND_WORD = {ip: "IP", domain: "域名", url: "URL", file_hash: "文件", keyword: "关键词"};
const V = {
  malicious: {label: "恶意", glyph: "☣"},
  suspicious: {label: "可疑", glyph: "!"},
  unknown: {label: "未知", glyph: "?"},
  keyword: {label: "检索", glyph: "⌕"},
};
const ICON = {
  copy: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>`,
  search: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>`,
  link: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></svg>`,
  card: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="12" r="2.2"/><path d="M14 10h4M14 14h4"/></svg>`,
  at: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M16 12v1.5a2.5 2.5 0 0 0 5 0V12a9 9 0 1 0-3.5 7.1"/></svg>`,
  book: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M4 21V5"/></svg>`,
  target: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/></svg>`,
  export: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12M7 10l5 5 5-5M5 21h14"/></svg>`,
};

function esc(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c])); }
const num = n => (n ?? 0).toLocaleString("zh-CN");
const qlink = v => "#/search?q=" + encodeURIComponent(v);
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.classList.add("show"); setTimeout(() => t.classList.remove("show"), 1600); }
function copy(text) {
  const done = () => toast("已复制");
  if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
  else fallbackCopy(text, done);
}
function fallbackCopy(text, done) {
  const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); done(); } catch (e) {} ta.remove();
}
let pending = 0;
function progress(delta) {
  pending = Math.max(0, pending + delta);
  const bar = $("#topbar");
  if (!bar) return;
  if (pending) { bar.classList.remove("done"); bar.classList.add("run"); }
  else { bar.classList.add("done"); setTimeout(() => { if (!pending) bar.classList.remove("run", "done"); }, 350); }
}
async function api(path, opts) {
  progress(1);
  try {
    const init = {credentials: "same-origin", headers: {"Accept": "application/json"}, ...(opts || {})};
    if (init.body && typeof init.body === "object" && !(init.body instanceof FormData)) {
      init.headers = {...(init.headers || {}), "Content-Type": "application/json"};
      init.body = JSON.stringify(init.body);
    }
    const r = await fetch(path, init);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ("请求失败（HTTP " + r.status + "）"));
    return j;
  } finally { progress(-1); }
}
function safeUrl(u) { return /^https?:\/\/[^\s<>"']+$/i.test(String(u || "")) ? u : ""; }

/* 前端只做类型提示，真正的识别和校验在后端 */
const RE = {
  ip: /^\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?$/,
  hash: /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i,
  url: /^[a-z][a-z0-9+.-]*:\/\//i,
  domain: /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\.?$/i,
};
function refang(s) {
  return String(s || "").trim().replace(/^hxxp/i, "http").replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".").replace(/\[:\]/g, ":").replace(/\[:\/\/\]/g, "://");
}
function detectKind(raw) {
  const s = refang(raw);
  if (!s) return "";
  if (RE.ip.test(s)) return "IP";
  if (RE.hash.test(s)) return {32: "MD5", 40: "SHA1", 64: "SHA256"}[s.length];
  if (RE.url.test(s)) return "URL";
  if (RE.domain.test(s)) return "域名";
  return s.length >= 3 ? "家族 / 关键词" : "";
}

const RECENT_KEY = "hunti.recent";
const VISIT_KEY = "hunti.lastVisit";
const SESSION_SINCE_KEY = "hunti.sessionSince";
const STATUS_SIG_KEY = "hunti.statusSig";

function recentList() {
  try { return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]").filter(x => typeof x === "string").slice(0, 8); } catch (e) { return []; }
}
function pushRecent(v) {
  try {
    const list = [v, ...recentList().filter(x => x !== v)].slice(0, 8);
    localStorage.setItem(RECENT_KEY, JSON.stringify(list));
  } catch (e) {}
}

/** 本次会话用来对比「新增」的基准时间（上次离开时写入的 lastVisit） */
function visitSince() {
  try {
    const ok = n => Number.isFinite(n) && n > 0 ? n : 0;
    const cached = sessionStorage.getItem(SESSION_SINCE_KEY);
    if (cached != null && cached !== "") return ok(parseInt(cached, 10));
    const prev = ok(parseInt(localStorage.getItem(VISIT_KEY) || "0", 10));
    sessionStorage.setItem(SESSION_SINCE_KEY, String(prev));
    return prev;
  } catch (e) { return 0; }
}
function bumpVisit() {
  try { localStorage.setItem(VISIT_KEY, String(Math.floor(Date.now() / 1000))); } catch (e) {}
}
function markUpdatesRead() {
  bumpVisit();
  try { sessionStorage.setItem(SESSION_SINCE_KEY, String(Math.floor(Date.now() / 1000))); } catch (e) {}
  toast("已标记为已读");
  if ((location.hash || "#/") === "#/" || (location.hash || "").startsWith("#/?")) route();
  else if ((location.hash || "").startsWith("#/intel")) route();
}
function sinceQuery() {
  const s = visitSince();
  return s > 0 ? "&since=" + s : "";
}
function newBadge(a) {
  return a && a.is_new ? `<span class="badge-new">NEW</span>` : "";
}

let _statusCache = null;
let _statusTimer = 0;
function fmtNum(n) {
  if (n == null) return "…";
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
  if (n >= 1e4) return (n / 1e3).toFixed(1).replace(/\.0$/, "") + "k";
  return num(n);
}
function renderStatusBar(d) {
  const el = $("#navStatus");
  if (!el) return;
  _statusCache = d;
  const ageH = d.db_mtime ? (Date.now() / 1000 - d.db_mtime) / 3600 : 999;
  const dot = !d.ok ? "bad" : ageH > 48 ? "warn" : "";
  const tip = !d.ok ? "情报库不可用" : ageH > 48 ? "库超过 48 小时未更新" : "库状态正常";
  el.innerHTML = `<span class="st-dot ${dot}" title="${tip}"></span>
    <span class="st-item" title="IOC 记录数"><b>${fmtNum(d.ioc_count)}</b>IOC</span>
    <span class="st-item" title="情报文章"><b>${fmtNum(d.article_count)}</b>文</span>
    <span class="st-item" title="今日新增文章"><b>${fmtNum(d.today_articles)}</b>今日</span>
    <span class="st-upd" title="库文件时间">${esc(d.db_mtime_iso || "—")}</span>`;
}
async function refreshStatus(silent) {
  try {
    // 状态轮询不走顶部进度条，避免每分钟闪一下
    const r = await fetch("/api/status", {credentials: "same-origin", headers: {"Accept": "application/json"}});
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || "status failed");
    const prev = localStorage.getItem(STATUS_SIG_KEY) || "";
    const changed = !!(prev && d.intel_sig && prev !== d.intel_sig);
    renderStatusBar(d);
    if (changed) {
      // 会话内检测到情报文件变化：提示并给出刷新按钮
      if (!silent) toast("情报源已更新，点击刷新查看");
      const el = $("#navStatus");
      if (el && !el.querySelector(".st-refresh")) {
        const btn = document.createElement("button");
        btn.className = "st-refresh";
        btn.textContent = "刷新";
        btn.onclick = () => {
          try { localStorage.setItem(STATUS_SIG_KEY, d.intel_sig || ""); } catch (e) {}
          location.reload();
        };
        el.appendChild(btn);
      }
    } else if (d.intel_sig) {
      try { localStorage.setItem(STATUS_SIG_KEY, d.intel_sig); } catch (e) {}
    }
    return d;
  } catch (e) {
    const el = $("#navStatus");
    if (el) el.innerHTML = `<span class="st-dot bad"></span><span class="st-upd">状态不可用</span>`;
    return null;
  }
}
function startStatusPoll() {
  refreshStatus(true);
  if (_statusTimer) clearInterval(_statusTimer);
  _statusTimer = setInterval(() => refreshStatus(false), 60000);
  window.addEventListener("beforeunload", bumpVisit);
  // 打开超过 2 分钟也记一次，避免标签页挂一整晚导致 NEW 永远不清
  setTimeout(bumpVisit, 120000);
}
function skel(n = 4) { return Array.from({length: n}, (_, i) => `<div class="skel" style="width:${90 - i * 11}%"></div>`).join(""); }
function uniq(list) {
  const seen = new Set();
  return (list || []).filter(t => { const k = String(t).toLowerCase(); if (!t || seen.has(k)) return false; seen.add(k); return true; });
}

const PLACEHOLDER = {
  all: "请输入 IP、域名、URL、文件哈希或恶意家族名进行查询",
  ip: "请输入 IP，例如 1.2.3.4 或 1.2.3.4:8080",
  domain: "请输入域名，例如 example.com",
  url: "请输入 URL，支持 hxxp:// 与 [.] 去活写法",
  file_hash: "请输入 MD5 / SHA1 / SHA256",
  keyword: "请输入恶意家族或关键词，例如 AsyncRAT",
};
function searchBox(size, value = "") {
  const id = "f" + Math.random().toString(36).slice(2, 8);
  setTimeout(() => {
    const f = document.getElementById(id);
    if (!f) return;
    const input = f.querySelector("input"), badge = f.querySelector(".kind");
    const upd = () => { const k = detectKind(input.value); badge.textContent = k ? "识别为 " + k : ""; badge.classList.toggle("show", !!k); };
    input.addEventListener("input", upd);
    upd();
    f.addEventListener("submit", e => {
      e.preventDefault();
      const v = input.value.trim().slice(0, 512);
      if (!v) { input.focus(); return; }
      pushRecent(v);
      f.querySelector("button").classList.add("busy");
      const h = qlink(v);
      if (location.hash === h) route(); else location.hash = h;
    });
  });
  const ph = size === "sm" ? "搜索 IP / 域名 / URL / 哈希" : PLACEHOLDER.all;
  return `<form class="sbox ${size}" id="${id}" autocomplete="off" role="search">
    <input name="q" value="${esc(value)}" maxlength="512" spellcheck="false" placeholder="${ph}" aria-label="威胁情报查询" ${size === "lg" ? "autofocus" : ""}>
    <span class="kind"></span>
    <button type="submit">${ICON.search}${size === "sm" ? "" : "搜 索"}</button></form>`;
}

function tagList(a, limit) {
  const actors = uniq(a.actors);
  const seen = new Set(actors.map(t => t.toLowerCase()));
  const mal = uniq(a.malware).filter(t => !seen.has(t.toLowerCase()));
  return actors.slice(0, limit).map(t => `<a class="tag orange" href="${qlink(t)}">${esc(t)}</a>`).join("")
    + mal.slice(0, limit).map(t => `<a class="tag red" href="${qlink(t)}">${esc(t)}</a>`).join("");
}
const CAT_LABEL = {blog: "安全博客", tc: "威胁通报", otx: "OTX 情报包", campaign: "战役报告", apt: "APT 研究", research: "恶意软件研究",
  tf: "ThreatFox 引用", yara: "YARA 规则", malpedia: "Malpedia 文献"};
function catBadges(a, max = 3) {
  return (a.cats || [a.cat]).filter(Boolean).slice(0, max)
    .map(c => `<span class="cat cat-${esc(c)}">${esc(CAT_LABEL[c] || c)}</span>`).join("");
}
function topicBadges(a, max = 3) {
  return (a.topics || []).filter(t => TOPIC_LABEL[t]).slice(0, max)
    .map(t => `<a class="topic-tag topic-${esc(t)}" href="#/intel?topic=${esc(t)}">${esc(TOPIC_LABEL[t])}</a>`).join("");
}
function articleItem(a) {
  const ic = a.ioc_count ? `<span class="tag blue">IOC ${num(a.ioc_count)}</span>` : "";
  const tags = tagList(a, 4);
  return `<div class="art"><div class="meta">${catBadges(a, 1)}${topicBadges(a, 2)}<b>${esc(a.source)}</b><span>${esc(a.date)}</span></div>
    <a class="title" data-aid="${a.id}">${esc(a.title)}${newBadge(a)}</a>
    ${a.summary ? `<div class="sum">${esc(a.summary)}</div>` : ""}
    ${(ic || tags) ? `<div class="afoot">${ic}${tags}</div>` : ""}</div>`;
}
function bindArticles(root) { root.querySelectorAll("[data-aid]").forEach(el => el.addEventListener("click", () => openArticle(+el.dataset.aid))); }
function segment(el, onChange) {
  el.querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
    el.querySelectorAll("button").forEach(x => x.classList.toggle("on", x === b));
    onChange(b.dataset.v);
  }));
}

/* ================= 首页 ================= */
const TOPIC_LABEL = {apt: "APT", c2: "C2", cybercrime: "黑产", ransomware: "勒索"};
const HOME_SIDE_TOPICS = [
  {key: "apt", title: "APT", desc: "定向攻击 / 国家级威胁", color: "#d4282d"},
  {key: "c2", title: "C2", desc: "命令控制与恶意基础设施", color: "#2c6cf6"},
  {key: "cybercrime", title: "黑产", desc: "窃密 / 钓鱼 / 灰产", color: "#c75a0a"},
  {key: "ransomware", title: "勒索", desc: "勒索软件与双敲勒索", color: "#b45309"},
];

function renderHome() {
  view.innerHTML = `
  <section class="hero"><div class="wrap">
    <div class="hero-logo"><svg viewBox="0 0 32 32" fill="none"><path d="M16 2l11 4.5v8.3c0 7-4.7 12.6-11 15.2C9.7 27.4 5 21.8 5 14.8V6.5L16 2z" fill="#2c6cf6"/><path d="M16 6.2l7.6 3.1v5.6c0 4.8-3.2 8.8-7.6 10.7-4.4-1.9-7.6-5.9-7.6-10.7V9.3L16 6.2z" fill="#0b1736"/><circle cx="16" cy="15.2" r="3.4" fill="#5fd0ff"/></svg>威胁情报中心</div>
    <div class="sub">IP · 域名 · URL · 文件哈希 · 恶意家族 一站式威胁研判</div>
    <div class="search-area">
      <div class="stype" id="stype">
        <button data-v="all" class="on">全部</button><button data-v="ip">IP</button><button data-v="domain">域名</button>
        <button data-v="url">URL</button><button data-v="file_hash">文件</button><button data-v="keyword">家族</button>
      </div>
      ${searchBox("lg")}
      <div class="hint">自动识别查询类型，支持直接粘贴 hxxp:// 、[.] 等去活写法 · 按 <b style="color:#fff">/</b> 快速聚焦搜索框</div>
      <div class="recent" id="recent"></div>
    </div>
  </div></section>
  <div class="wrap">
    <div class="feature">
      ${[["IP", "#2c6cf6", "IP 研判", "C2 服务器、恶意端口、关联 URL"],
         ["域", "#0b8a7d", "域名研判", "恶意域名、父域名、同主机 URL"],
         ["URL", "#6a43d9", "URL 研判", "钓鱼 / 投递链接与所在主机"],
         ["#", "#c75a0a", "样本研判", "MD5 / SHA1 / SHA256 恶意样本"]]
        .map(([i, c, t, s]) => `<div class="f"><span class="ic" style="background:${c}">${i}</span><div><b>${t}</b><span>${s}</span></div></div>`).join("")}
    </div>
    <div class="home-grid">
      <div class="card feed-card">
        <div class="card-h">
          <div class="nh"><h3>情报速览</h3><span class="muted">本地情报库最新文章，可按专项筛选</span></div>
          <div class="r"><a class="btn" id="feedMore" href="#/intel">查看全部</a></div>
        </div>
        <div id="homeNewBar"></div>
        <div class="feed-tabs" id="feedTabs">
          <button data-v="latest" class="on">最新</button>
          <button data-v="apt">APT</button>
          <button data-v="c2">C2</button>
          <button data-v="cybercrime">黑产</button>
          <button data-v="ransomware">勒索</button>
          <button data-v="ioc">含 IOC</button>
        </div>
        <div class="card-b" id="arts">${skel(8)}</div>
        <div class="pager" id="feedPager"></div>
      </div>
      <aside class="home-side">
        <div class="card">
          <div class="card-h"><h3>快捷入口</h3></div>
          <div class="side-links" id="sideLinks">
            <a href="#/" id="btnSubmit" class="submit-link"><i style="background:#0b8a7d">+</i><span>提交情报</span></a>
            <a href="#/batch"><i style="background:#2c6cf6">批</i><span>批量研判</span></a>
            <a href="#/apt"><i style="background:#d4282d">APT</i><span>APT / 家族</span></a>
            <a href="#/watch"><i style="background:#b07c00">★</i><span>关注列表</span></a>
            <a href="#/intel?cat=campaign"><i style="background:#6a43d9">战</i><span>战役报告</span></a>
            <a href="#/intel"><i style="background:#1f7ae0">讯</i><span>情报动态</span></a>
          </div>
        </div>
        <div class="card">
          <div class="card-h"><h3>本轮采集</h3><span class="muted" style="font-size:12px" id="pipeWhen"></span></div>
          <div class="card-b" id="pipeSum">${skel(2)}</div>
        </div>
        <div class="card">
          <div class="card-h"><h3>专项情报</h3><span class="muted" style="font-size:12px">run_all 更新后自动归类</span></div>
          <div class="side-topics" id="sideTopics">${skel(3)}</div>
        </div>
        <div class="card">
          <div class="card-h"><h3>热门标签</h3><span class="muted" style="font-size:12px">近期文章</span></div>
          <div class="card-b hot" id="hot">${skel(3)}</div>
        </div>
        <div class="card">
          <div class="card-h"><h3>暗网勒索</h3><div class="r"><a class="btn" href="#/darkweb">全部</a></div></div>
          <div class="card-b" id="dark">${skel(6)}</div>
        </div>
        <div class="card">
          <div class="card-h"><h3>关注动态</h3><div class="r"><a class="btn" href="#/watch">管理</a></div></div>
          <div class="card-b" id="homeWatch">${skel(2)}</div>
        </div>
        <div class="card dfill">
          <div class="card-h"><h3>最近查询</h3></div>
          <div class="card-b"><div class="rq" id="homeRecent"></div></div>
        </div>
      </aside>
    </div>
  </div>`;
  const input = $(".hero .sbox input");
  segment($("#stype"), v => { input.placeholder = PLACEHOLDER[v]; input.focus(); });
  renderRecent();
  loadHomeSide();
  $("#btnSubmit")?.addEventListener("click", e => { e.preventDefault(); openSubmitModal(); });
  const FEED_SIZE = 12;
  let feedMode = "latest";
  let feedPage = 1;
  const loadArts = async (mode, page) => {
    if (mode) { feedMode = mode; feedPage = 1; }
    if (page) feedPage = page;
    const el = $("#arts");
    const more = $("#feedMore");
    const qs = new URLSearchParams({
      offset: String((feedPage - 1) * FEED_SIZE),
      limit: String(FEED_SIZE),
      with_ioc: feedMode === "ioc" ? "1" : "0",
    });
    if (TOPIC_LABEL[feedMode]) qs.set("topic", feedMode);
    const s = visitSince();
    if (s > 0) qs.set("since", String(s));
    if (more) {
      more.href = TOPIC_LABEL[feedMode] ? `#/intel?topic=${feedMode}`
        : feedMode === "ioc" ? "#/intel" : "#/intel?ioc=0";
    }
    try {
      const d = await api("/api/articles?" + qs.toString());
      const pages = Math.max(1, Math.ceil((d.total || 0) / FEED_SIZE));
      if (feedPage > pages && d.total) { feedPage = pages; return loadArts(null, pages); }
      el.innerHTML = d.items.length ? d.items.map(articleItem).join("") : `<div class="empty">暂无情报文章</div>`;
      bindArticles(el);
      renderHomeNewBar(d);
      const pg = $("#feedPager");
      if (pg) {
        pg.innerHTML = pages > 1
          ? `<span class="muted">共 ${num(d.total)} 篇 · 第 ${feedPage} / ${pages} 页</span>
             <div class="pgs">${pager(feedPage, pages)}</div>
             <span class="pg-jump">跳至 <input type="number" min="1" max="${pages}" value="${feedPage}"> 页</span>`
          : (d.total ? `<span class="muted">共 ${num(d.total)} 篇</span>` : "");
        pg.querySelectorAll(".pg[data-p]").forEach(b => b.addEventListener("click", () => {
          const p = +b.dataset.p;
          if (p >= 1 && p <= pages) {
            loadArts(null, p);
            $(".feed-card")?.scrollIntoView({behavior: "smooth", block: "start"});
          }
        }));
        const jump = pg.querySelector(".pg-jump input");
        if (jump) jump.addEventListener("keydown", e => {
          if (e.key !== "Enter") return;
          loadArts(null, Math.min(pages, Math.max(1, parseInt(jump.value, 10) || 1)));
        });
      }
    } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
  };
  $("#feedTabs").querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
    $("#feedTabs").querySelectorAll("button").forEach(x => x.classList.toggle("on", x === b));
    loadArts(b.dataset.v, 1);
  }));
  loadArts("latest", 1);
}

function renderHomeNewBar(d) {
  const bar = $("#homeNewBar");
  if (!bar) return;
  const n = d && d.new_total;
  if (!n) { bar.innerHTML = ""; bar.className = ""; return; }
  const since = visitSince();
  const when = since ? new Date(since * 1000).toLocaleString("zh-CN", {month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit"}) : "";
  bar.className = "home-newbar";
  bar.innerHTML = `<div class="nb-text">自上次打开后新增 <b>${num(n)}</b> 篇${when ? `<span class="muted"> · 基准 ${esc(when)}</span>` : ""}</div>
    <div class="nb-acts"><button class="btn mark-read" id="markRead">标记已读</button>
    <a class="btn" href="#/intel?ioc=0">查看全部新增</a></div>`;
  const btn = $("#markRead");
  if (btn) btn.onclick = markUpdatesRead;
}

function renderSideTopics(topics, darkCount) {
  const box = $("#sideTopics");
  if (!box) return;
  const map = Object.fromEntries((topics || []).map(t => [t.key, t.count]));
  box.innerHTML = HOME_SIDE_TOPICS.map(t => `<a class="side-topic" href="#/intel?topic=${t.key}">
      <span class="st-mark" style="background:${t.color}">${esc(t.title)}</span>
      <span class="st-body"><b>${esc(t.title)} 专项</b><span>${esc(t.desc)}</span></span>
      <span class="st-n">${num(map[t.key] || 0)}</span></a>`).join("")
    + `<a class="side-topic dark" href="#/darkweb">
      <span class="st-mark" style="background:#7c2d12">暗网</span>
      <span class="st-body"><b>勒索暗网</b><span>泄露站点与团伙动态</span></span>
      <span class="st-n">${darkCount != null ? num(darkCount) : "›"}</span></a>`;
}

function loadHomeSide() {
  api("/api/topics").then(d => {
    renderSideTopics(d.topics || [], d.darkweb_count);
  }).catch(() => {});
  api("/api/hot_tags?limit=14").then(rows => {
    const el = $("#hot");
    if (!el) return;
    el.innerHTML = rows.length ? rows.map(t => `<a class="tag ${t.kind === "malware" ? "red" : "orange"}" href="${qlink(t.name)}">${t.kind === "malware" ? "☣ " : ""}${esc(t.name)}<i>${t.count}</i></a>`).join("")
      : `<div class="empty">暂无标签</div>`;
  }).catch(() => { const el = $("#hot"); if (el) el.innerHTML = `<div class="empty">暂无标签</div>`; });
  api("/api/pipeline_summary").then(p => {
    const el = $("#pipeSum");
    if (!el) return;
    const st = _statusCache || {};
    $("#pipeWhen").textContent = p.last_run ? `run_all ${p.last_run}` : "";
    const tl = {ip: "IP", domain: "域名", url: "URL", file_hash: "哈希"};
    el.innerHTML = `<div class="pipe">
        <div><b>${num(p.new_total)}</b><span>本轮新入库 IOC</span></div>
        <div><b>${st.today_articles != null ? num(st.today_articles) : "…"}</b><span>今日新文章</span></div>
        <div><b>${st.ioc_count != null ? fmtNum(st.ioc_count) : "…"}</b><span>主库 IOC</span></div>
        <div><b>${num(p.runs_7d)}</b><span>近 7 天采集次数</span></div>
      </div>
      ${Object.keys(p.by_type || {}).length ? `<div class="pipe-t">${Object.entries(p.by_type).sort((a, b) => b[1] - a[1]).map(([t, n]) => `<span class="tbadge t-${esc(t)}">${esc(tl[t] || t)} ${num(n)}</span>`).join("")}</div>` : ""}
      ${(p.by_source || []).length ? `<div class="pipe-s muted">主要来源：${p.by_source.map(([s, n]) => `${esc(s)} ${num(n)}`).join(" · ")}</div>` : ""}
      ${!p.last_run ? `<div class="muted" style="font-size:12px">还没有 run_all 的新增记录，运行一次后这里显示本轮新入库情况</div>` : ""}
      ${st.db_mtime_iso ? `<div class="pipe-s muted">主库更新于 ${esc(st.db_mtime_iso)}</div>` : ""}`;
  }).catch(() => { const el = $("#pipeSum"); if (el) el.innerHTML = `<div class="empty">暂无数据</div>`; });
  api("/api/watch").then(w => {
    const el = $("#homeWatch");
    if (!el) return;
    setWatchBadge(w.total_new || 0);
    const items = (w.items || []).slice(0, 5);
    el.innerHTML = items.length ? items.map(it => `<a class="hw ${it.new_total ? "has-new" : ""}" href="#/watch">
        <span class="tbadge t-${esc(it.kind)}">${esc(it.kind === "keyword" ? "家族" : (TYPE_LABEL[it.kind] || it.kind))}</span>
        <span class="mono hwv">${esc(it.value)}</span>
        ${it.new_total ? `<span class="wnew">${it.new_ioc_count ? `IOC ${num(it.new_ioc_count)}` : ""}${it.new_ioc_count && it.new_article_count ? " · " : ""}${it.new_article_count ? `文章 ${num(it.new_article_count)}` : ""}</span>` : `<span class="muted" style="font-size:12px">无新命中</span>`}
      </a>`).join("") + (w.total > items.length ? `<div class="muted" style="font-size:12px;padding-top:6px">共 ${num(w.total)} 项</div>` : "")
      : `<div class="muted" style="font-size:13px;padding:6px 0">还没有关注项。在研判结果或专题页点「☆ 关注」，run_all 后有新 IOC / 新文章会在这里提醒</div>`;
  }).catch(() => { const el = $("#homeWatch"); if (el) el.innerHTML = `<div class="muted" style="font-size:13px">关注接口不可用，请重启面板</div>`; });
  const rq = $("#homeRecent");
  if (rq) rq.innerHTML = recentList().map(v => `<a href="${qlink(v)}" title="${esc(v)}"><span class="tbadge">${esc(detectKind(v) || "关键词")}</span><span class="mono rv">${esc(v)}</span></a>`).join("")
    || `<span class="muted" style="font-size:13px">暂无查询记录</span>`;
  api("/api/darkweb?limit=5").then(d => {
    const el = $("#dark");
    if (!el) return;
    el.innerHTML = d.items.length ? d.items.map(darkRow).join("") : `<div class="empty">暂无数据</div>`;
    bindDark(el);
  }).catch(() => { const el = $("#dark"); if (el) el.innerHTML = `<div class="empty">暂无数据</div>`; });
}

/* ================= 用户提交情报 ================= */
function openSubmitModal() {
  const mask = $("#mask"), modal = $("#modal");
  mask.classList.add("show");
  modal.innerHTML = `<div class="modal-h"><div style="min-width:0">
      <h2>提交情报</h2>
      <div class="muted" style="font-size:12px;margin-top:4px">粘贴 IOC 即可入库本地「用户提交」库，可被搜索命中；不写入主库 ioc_data.db</div>
    </div><button class="x" id="mx">×</button></div>
    <div class="modal-b submit-form">
      <label>IOC 列表<span class="muted">每行一条，支持 IP / 域名 / URL / MD5·SHA1·SHA256，可用 hxxp / [.]</span></label>
      <textarea id="subText" rows="10" placeholder="45.1.2.3&#10;evil.example.com&#10;http://evil.example.com/path&#10;d41d8cd98f00b204e9800998ecf8427e"></textarea>
      <div class="submit-row">
        <div><label>恶意家族（可选）</label><input id="subMal" maxlength="80" placeholder="如 Mirai / LockBit"></div>
        <div><label>来源标签（可选）</label><input id="subSrc" maxlength="80" placeholder="默认：用户提交"></div>
      </div>
      <label>备注（可选）</label>
      <input id="subNote" maxlength="200" placeholder="简要说明来源或关联案件">
      <div class="submit-acts">
        <button class="btn" id="subCancel">取消</button>
        <button class="btn primary" id="subGo">提交</button>
      </div>
      <div class="muted" id="subHint" style="margin-top:10px;font-size:12px">已提交的情报保存在 output/intel/user_iocs.json</div>
    </div>`;
  $("#mx").onclick = $("#subCancel").onclick = closeModal;
  $("#subGo").onclick = async () => {
    const text = $("#subText").value.trim();
    if (!text) { toast("请先粘贴 IOC"); return; }
    const btn = $("#subGo");
    btn.disabled = true;
    try {
      const r = await api("/api/user_intel", {
        method: "POST",
        body: {text, malware: $("#subMal").value.trim(), source: $("#subSrc").value.trim(), note: $("#subNote").value.trim()},
      });
      toast(`已新增 ${r.added} 条` + (r.skipped ? `，跳过重复 ${r.skipped} 条` : ""));
      closeModal();
    } catch (e) {
      toast(e.message || "提交失败");
      btn.disabled = false;
    }
  };
  setTimeout(() => $("#subText")?.focus(), 50);
}

function renderRecent() {
  const box = $("#recent");
  if (!box) return;
  const list = recentList();
  if (!list.length) { box.innerHTML = ""; return; }
  box.innerHTML = `<span class="lbl">最近查询：</span>` + list.map(v => `<a href="${qlink(v)}" title="${esc(v)}">${esc(v)}</a>`).join("")
    + `<button id="clrRecent" title="清空">清空</button>`;
  $("#clrRecent").onclick = () => { try { localStorage.removeItem(RECENT_KEY); } catch (e) {} renderRecent(); };
}

/* ================= 情报动态 ================= */
const AV_COLORS = ["#2c6cf6", "#0b8a7d", "#6a43d9", "#c75a0a", "#d4282d", "#1f7ae0", "#7a5af5", "#0e9f6e", "#b45309", "#be185d"];
function avatar(name) {
  const s = String(name || "?");
  let h = 0;
  for (const ch of s) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  const ini = /^[a-z0-9]/i.test(s) ? s.replace(/[^a-z0-9]/gi, "").slice(0, 2).toUpperCase() || "?" : s.slice(0, 1);
  return `<span class="av" style="background:${AV_COLORS[h % AV_COLORS.length]}">${esc(ini)}</span>`;
}
const IOC_ORDER = ["ip", "domain", "url", "md5", "sha1", "sha256", "file_hash"];
function iocChips(types) {
  return IOC_ORDER.filter(t => types && types[t]).map(t => `<span class="tbadge t-${t}">${esc(TYPE_LABEL[t] || t)} ${num(types[t])}</span>`).join("");
}
function intelCard(a) {
  const link = safeUrl(a.url);
  return `<div class="acard">
    ${avatar(a.source)}
    <div class="abody">
      <div class="ameta">${catBadges(a)}<b>${esc(a.source || "未知来源")}</b><span>${esc(a.date)}</span>${a.ioc_count ? `<span class="aioc">IOC ${num(a.ioc_count)}</span>` : ""}${newBadge(a)}</div>
      <a class="atitle" data-aid="${a.id}" role="button" tabindex="0">${esc(a.title)}</a>
      ${a.summary ? `<div class="asum">${esc(a.summary)}</div>` : ""}
      <div class="afoot">${iocChips(a.ioc_types)}${tagList(a, 5)}</div>
    </div>
    <div class="aside">
      <button class="btn" data-aid="${a.id}">${a.ioc_count ? "查看 IOC" : "查看详情"}</button>
      ${link ? `<a class="btn" href="${esc(link)}" target="_blank" rel="noopener noreferrer">原文 ↗</a>` : ""}
    </div></div>`;
}
function pager(page, pages) {
  if (pages <= 1) return "";
  const nums = new Set([1, pages, page - 2, page - 1, page, page + 1, page + 2].filter(p => p >= 1 && p <= pages));
  const list = [...nums].sort((a, b) => a - b);
  let html = `<button class="pg" data-p="${page - 1}" ${page <= 1 ? "disabled" : ""}>‹ 上一页</button>`;
  let last = 0;
  for (const p of list) {
    if (p - last > 1) html += `<span class="pg-gap">…</span>`;
    html += `<button class="pg ${p === page ? "on" : ""}" data-p="${p}">${p}</button>`;
    last = p;
  }
  html += `<button class="pg" data-p="${page + 1}" ${page >= pages ? "disabled" : ""}>下一页 ›</button>`;
  return html;
}

function intelHash(st) {
  const p = new URLSearchParams();
  if (st.page > 1) p.set("page", st.page);
  if (st.size !== 20) p.set("size", st.size);
  if (!st.ioc) p.set("ioc", "0");
  if (st.days) p.set("days", st.days);
  if (st.cat) p.set("cat", st.cat);
  if (st.topic) p.set("topic", st.topic);
  if (st.source) p.set("source", st.source);
  if (st.q) p.set("q", st.q);
  const s = p.toString();
  return "#/intel" + (s ? "?" + s : "");
}

async function renderIntel(params) {
  const dayOpt = [0, 1, 3, 7];
  const st = {
    page: Math.max(1, parseInt(params.get("page") || "1", 10) || 1),
    size: [20, 30, 50].includes(+params.get("size")) ? +params.get("size") : 20,
    ioc: params.get("ioc") !== "0",
    days: dayOpt.includes(+params.get("days")) ? +params.get("days") : 0,
    cat: CAT_LABEL[params.get("cat")] ? params.get("cat") : "",
    topic: TOPIC_LABEL[params.get("topic")] ? params.get("topic") : "",
    source: (params.get("source") || "").slice(0, 100),
    q: (params.get("q") || "").slice(0, 100),
  };
  const go = patch => { location.hash = intelHash({...st, page: 1, ...patch}); };
  const dayLabel = {0: "全部时间", 1: "今天", 3: "近 3 天", 7: "近 7 天"};
  const topicTitle = st.topic ? (TOPIC_LABEL[st.topic] + " 专项情报") : "情报动态";
  const topicDesc = st.topic === "apt" ? "自动归类的 APT / 定向攻击相关文章与报告"
    : st.topic === "c2" ? "自动归类的 C2 基础设施、Cobalt Strike / Sliver 等相关情报"
    : st.topic === "cybercrime" ? "自动归类的窃密、钓鱼与黑灰产相关情报"
    : st.topic === "ransomware" ? "自动归类的勒索软件、双敲与泄露站相关情报"
    : "下方分类统计的是「情报文章」篇数，不是主库 IOC 总量。主库数百万条 IOC 请用顶栏搜索命中；本页聚合博客 / 通报 / OTX / 战役 / APT / 研究 / YARA / Malpedia 等文章并提取文中 IOC";
  view.innerHTML = `
  <div class="ihead"><div class="wrap">
    <div class="ihead-in">
      <div><h1>${esc(topicTitle)}</h1><p>${esc(topicDesc)}</p></div>
      <form class="ifilter" id="ifilter" autocomplete="off">
        <input name="q" maxlength="100" value="${esc(st.q)}" placeholder="搜索标题、摘要、团伙、家族…" aria-label="搜索情报文章">
        <button type="submit">${ICON.search}</button>
      </form>
    </div>
    <div class="topic-bar" id="topicBar"></div>
    <div class="istats" id="istats"></div>
  </div></div>
  <div class="wrap"><div class="ilayout">
    <div class="card">
      <div class="ctabs" id="ctabs">${skel(1)}</div>
      <div class="card-h">
        <div class="seg" id="iSeg"><button data-v="1" class="${st.ioc ? "on" : ""}" title="只显示正文提取到 IOC 的文章">仅含 IOC</button><button data-v="0" class="${st.ioc ? "" : "on"}" title="含无 IOC 的文章也显示，约两万三千篇">含无 IOC</button></div>
        <div class="seg" id="daySeg">${dayOpt.map(d => `<button data-v="${d}" class="${st.days === d ? "on" : ""}">${dayLabel[d]}</button>`).join("")}</div>
        ${st.topic ? `<span class="tag red">专项：${esc(TOPIC_LABEL[st.topic])} <a class="x-clear" data-clear="topic" role="button" tabindex="0">×</a></span>` : ""}
        ${st.source ? `<span class="tag blue">来源：${esc(st.source)} <a class="x-clear" data-clear="source" role="button" tabindex="0">×</a></span>` : ""}
        ${st.q ? `<span class="tag orange">关键词：${esc(st.q)} <a class="x-clear" data-clear="q" role="button" tabindex="0">×</a></span>` : ""}
        <div class="r">${visitSince() ? `<button class="btn mark-read" id="iMarkRead">标记已读</button>` : ""}
          <span class="muted" style="font-size:12px">每页</span>
          <select id="iSize" class="sel">${[20, 30, 50].map(n => `<option value="${n}" ${n === st.size ? "selected" : ""}>${n} 篇</option>`).join("")}</select></div>
      </div>
      <div id="ilist">${skel(10)}</div>
      <div class="pager" id="ipager"></div>
    </div>
    <div class="dcol iside">
      <div class="card"><div class="side-h">专项情报<span class="muted" style="font-weight:400;font-size:12px">点击筛选</span></div><div class="side-topics" id="sideTopics">${skel(3)}</div></div>
      <div class="card"><div class="side-h">情报来源<span class="muted" style="font-weight:400;font-size:12px">点击筛选，再点取消</span></div><div class="side-b"><div class="srclist" id="isrc">${skel(6)}</div></div></div>
      <div class="card"><div class="side-h">热门标签</div><div class="side-b"><div class="hot" id="itags">${skel(3)}</div></div></div>
      <div class="card"><div class="side-h">暗网勒索<a class="btn" href="#/darkweb" style="margin-left:auto">全部</a></div><div class="side-b" id="idark">${skel(4)}</div></div>
    </div>
  </div></div>`;

  $("#ifilter").addEventListener("submit", e => { e.preventDefault(); go({q: e.target.q.value.trim().slice(0, 100)}); });
  segment($("#iSeg"), v => go({ioc: v === "1"}));
  segment($("#daySeg"), v => go({days: +v}));
  $("#iSize").addEventListener("change", e => go({size: +e.target.value}));
  view.querySelectorAll("[data-clear]").forEach(el => el.addEventListener("click", () => go({[el.dataset.clear]: ""})));
  const markBtn = $("#iMarkRead");
  if (markBtn) markBtn.onclick = markUpdatesRead;

  const qs = new URLSearchParams({offset: (st.page - 1) * st.size, limit: st.size, with_ioc: st.ioc ? "1" : "0"});
  if (st.days) qs.set("days", st.days);
  if (st.cat) qs.set("cat", st.cat);
  if (st.topic) qs.set("topic", st.topic);
  if (st.source) qs.set("source", st.source);
  if (st.q) qs.set("q", st.q);
  const since = visitSince();
  if (since) qs.set("since", since);
  const seq = routeSeq;
  let d;
  try { d = await api("/api/articles?" + qs.toString()); }
  catch (e) { if (seq === routeSeq) $("#ilist").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  if (seq !== routeSeq) return;
  const pages = Math.max(1, Math.ceil(d.total / st.size));
  if (st.page > pages && d.total) { location.hash = intelHash({...st, page: pages}); return; }

  const tbar = $("#topicBar");
  if (tbar) {
    const topics = d.topics || [];
    tbar.innerHTML = `<a class="tchip ${st.topic ? "" : "on"}" href="${intelHash({...st, topic: "", page: 1})}">全部</a>`
      + topics.map(t => `<a class="tchip ${st.topic === t.key ? "on" : ""}" href="${intelHash({...st, topic: t.key, page: 1})}">${esc(t.label)}<i>${num(t.count)}</i></a>`).join("");
  }

  $("#ctabs").innerHTML = [{key: "", label: "全部分类", count: d.all_count, count_all: d.all_count}, ...d.categories]
    .map(c => {
      const noIoc = st.ioc && !c.count && c.count_all;
      const dis = !c.count && !c.count_all && c.key !== st.cat;
      return `<button class="${c.key === st.cat ? "on" : ""} ${c.key ? "cat-" + esc(c.key) : ""} ${noIoc ? "noioc" : ""}" data-cat="${esc(c.key)}"
        ${noIoc ? 'data-all="1" title="该类别没有 IOC，点击查看全部文章"' : ""} ${dis ? "disabled" : ""}>
        <i class="dot-c"></i>${esc(c.label)}<span>${num(noIoc ? c.count_all : c.count)}</span></button>`;
    }).join("");
  $("#ctabs").querySelectorAll("button[data-cat]").forEach(b => b.addEventListener("click", () =>
    go({cat: b.dataset.cat, source: "", ...(b.dataset.all ? {ioc: false} : {})})));
  const stats = [
    ["文章", num(d.total), "当前筛选下的情报文章篇数"],
    ["文内 IOC", num(d.ioc_total), "这些文章里提取到的 IOC 合计"],
    ["主库 IOC", d.db_ioc_count != null ? num(d.db_ioc_count) : "…", "ioc_data.db 全库指标数，顶栏搜索用"],
    ["来源", num(d.source_total), ""],
    ["页码", `${st.page} / ${pages}`, ""],
  ];
  if (d.new_total) stats.splice(1, 0, ["新增", num(d.new_total), ""]);
  $("#istats").innerHTML = stats.map(([k, v, tip]) =>
    `<div${tip ? ` title="${esc(tip)}"` : ""}><b>${v}</b><span>${k}</span></div>`).join("");

  let html = "", lastDate = null;
  for (const a of d.items) {
    if (a.date !== lastDate) { html += `<div class="dhdr">${esc(a.date || "未知日期")}</div>`; lastDate = a.date; }
    html += intelCard(a);
  }
  $("#ilist").innerHTML = html || `<div class="empty" style="padding:60px 0">没有符合条件的情报文章</div>`;
  bindArticles($("#ilist"));
  $("#ilist").querySelectorAll(".atitle").forEach(el => el.addEventListener("keydown", e => { if (e.key === "Enter") openArticle(+el.dataset.aid); }));

  const pg = $("#ipager");
  pg.innerHTML = pages > 1 ? `<span class="muted">共 ${num(d.total)} 篇</span><div class="pgs">${pager(st.page, pages)}</div>
    <span class="pg-jump">跳至 <input id="pgIn" type="number" min="1" max="${pages}" value="${st.page}"> 页</span>` : "";
  pg.querySelectorAll(".pg[data-p]").forEach(b => b.addEventListener("click", () => {
    const p = +b.dataset.p;
    if (p >= 1 && p <= pages) location.hash = intelHash({...st, page: p});
  }));
  const jump = $("#pgIn");
  if (jump) jump.addEventListener("keydown", e => {
    if (e.key !== "Enter") return;
    const p = Math.min(pages, Math.max(1, parseInt(jump.value, 10) || 1));
    location.hash = intelHash({...st, page: p});
  });

  $("#isrc").innerHTML = (d.sources.length ? d.sources : []).map(s => `<a class="${s.name === st.source ? "on" : ""}" data-src="${esc(s.name)}" role="button" tabindex="0">
      ${avatar(s.name)}<span class="n">${esc(s.name)}</span><span class="c">${num(s.count)}</span></a>`).join("") || `<div class="empty">暂无</div>`;
  $("#isrc").querySelectorAll("[data-src]").forEach(el => el.addEventListener("click", () => go({source: el.dataset.src === st.source ? "" : el.dataset.src})));

  api("/api/topics").then(t => {
    if (seq !== routeSeq) return;
    renderSideTopics(t.topics || [], t.darkweb_count);
    $("#sideTopics")?.querySelectorAll(".side-topic").forEach(a => {
      const m = (a.getAttribute("href") || "").match(/topic=(\w+)/);
      if (m) a.classList.toggle("on", m[1] === st.topic);
    });
  }).catch(() => {});
  api("/api/darkweb?limit=5").then(r => {
    const el = $("#idark");
    if (!el || seq !== routeSeq) return;
    el.innerHTML = r.items.length ? r.items.map(darkRow).join("") : `<div class="empty">暂无数据</div>`;
    bindDark(el);
  }).catch(() => { const el = $("#idark"); if (el) el.innerHTML = `<div class="empty">暂无数据</div>`; });
  api("/api/hot_tags?limit=24").then(rows => {
    const box = $("#itags");
    if (!box) return;
    box.innerHTML = rows.map(t => `<a class="tag ${t.kind === "malware" ? "red" : "orange"}" data-kw="${esc(t.name)}" role="button" tabindex="0">${t.kind === "malware" ? "☣ " : ""}${esc(t.name)}<i>${t.count}</i></a>`).join("") || `<span class="muted">暂无</span>`;
    box.querySelectorAll("[data-kw]").forEach(el => el.addEventListener("click", () => go({q: el.dataset.kw})));
  }).catch(() => {});
}

/* ================= 搜索结果（详情页） ================= */
let routeSeq = 0;
/* 外部平台跳转：只拼公开查询页链接，不调接口、不需要 Key */
function pivotLinks(d) {
  const v = d.normalized, e = encodeURIComponent;
  const ip = d.kind === "ip" ? d.ip : "";
  const host = d.kind === "url" ? (d.host || "") : "";
  let L = [];
  if (ip) L = [
    ["VirusTotal", `https://www.virustotal.com/gui/ip-address/${e(ip)}`],
    ["微步", `https://x.threatbook.com/v5/ip/${e(ip)}`],
    ["ThreatFox", `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(ip)}`],
    ["OTX", `https://otx.alienvault.com/indicator/ip/${e(ip)}`],
    ["urlscan", `https://urlscan.io/search/#ip%3A${e(ip)}`],
    ["Shodan", `https://www.shodan.io/host/${e(ip)}`],
    ["AbuseIPDB", `https://www.abuseipdb.com/check/${e(ip)}`],
  ];
  else if (d.kind === "domain") L = [
    ["VirusTotal", `https://www.virustotal.com/gui/domain/${e(v)}`],
    ["微步", `https://x.threatbook.com/v5/domain/${e(v)}`],
    ["ThreatFox", `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(v)}`],
    ["OTX", `https://otx.alienvault.com/indicator/domain/${e(v)}`],
    ["urlscan", `https://urlscan.io/search/#domain%3A${e(v)}`],
    ["Shodan", `https://www.shodan.io/search?query=${e("hostname:" + v)}`],
    ["URLhaus", `https://urlhaus.abuse.ch/browse.php?search=${e(v)}`],
  ];
  else if (d.kind === "url") L = [
    ["VirusTotal", `https://www.virustotal.com/gui/search/${e(e(v))}`],
    ["微步", `https://x.threatbook.com/v5/url/${e(v)}`],
    ["ThreatFox", `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(v)}`],
    ["OTX", `https://otx.alienvault.com/indicator/url/${e(v)}`],
    ["urlscan", `https://urlscan.io/search/#${e('page.url:"' + v + '"')}`],
    ...(host ? [["Shodan", /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? `https://www.shodan.io/host/${e(host)}` : `https://www.shodan.io/search?query=${e("hostname:" + host)}`]] : []),
    ["URLhaus", `https://urlhaus.abuse.ch/browse.php?search=${e(v)}`],
  ];
  else if (d.kind === "file_hash") L = [
    ["VirusTotal", `https://www.virustotal.com/gui/file/${e(v)}`],
    ["微步", `https://s.threatbook.com/report/file/${e(v)}`],
    ["ThreatFox", `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(v)}`],
    ["OTX", `https://otx.alienvault.com/indicator/file/${e(v)}`],
    ["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=${e((v.length === 64 ? "sha256:" : v.length === 40 ? "sha1:" : "md5:") + v)}`],
    ["Triage", `https://tria.ge/s?q=${e(v)}`],
  ];
  else L = [
    ["ThreatFox", `https://threatfox.abuse.ch/browse.php?search=malware%3A${e(v)}`],
    ["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=${e("signature:" + v)}`],
    ["OTX", `https://otx.alienvault.com/browse/global/pulses?q=${e(v)}`],
    ["Malpedia", `https://malpedia.caad.fkie.fraunhofer.de/search?q=${e(v)}`],
    ["VirusTotal", `https://www.virustotal.com/gui/search/${e(e(v))}`],
  ];
  return `<div class="pivots"><span class="pv-l">外部平台</span>${L.map(([n, u]) =>
    `<a class="pv" href="${esc(u)}" target="_blank" rel="noopener noreferrer" title="在 ${esc(n)} 中查看（会把该指标发给第三方平台）">${esc(n)} ↗</a>`).join("")}</div>`;
}

function renderAbuse(r) {
  const box = document.querySelector("#abuseCard .side-b");
  if (!box) return;
  if (!r || r.configured === false) {
    box.innerHTML = `<span class="muted">未配置 Key：填写 config/abuseipdb_api_key.txt 或环境变量 ABUSEIPDB_API_KEY 后重启面板（免费版每天 1000 次）</span>`;
    return;
  }
  if (r.error) { box.innerHTML = `<span class="muted">${esc(r.error)}</span>`; return; }
  const s = Number(r.score) || 0;
  const cls = s >= 75 ? "hi" : s >= 25 ? "mid" : "lo";
  const row = (k, v) => v || v === 0 ? `<div class="ac-kv"><span class="k">${k}</span><span>${esc(String(v))}</span></div>` : "";
  const link = safeUrl(r.link);
  box.innerHTML = `<div class="abuse-score ${cls}"><b>${s}</b><span>% 滥用置信度</span></div>`
    + row("举报次数", r.total_reports) + row("举报用户", r.distinct_users)
    + row("最近举报", r.last_reported_at ? String(r.last_reported_at).slice(0, 19).replace("T", " ") : "")
    + row("国家", r.country) + row("ISP", r.isp) + row("域名", r.domain) + row("用途", r.usage_type)
    + (r.is_tor ? row("Tor", "是") : "") + (r.is_whitelisted ? row("白名单", "是") : "")
    + `<div class="muted" style="font-size:12px;margin-top:6px">${r.cached ? "本地缓存" : "实时查询"}${r.stale ? "（配额用完，显示旧结果）" : ""}${link ? ` · <a href="${esc(link)}" target="_blank" rel="noopener noreferrer">查看详情</a>` : ""}</div>`;
}

function actorCard(p) {
  if (!p) return "";
  const meta = [];
  if (p.country && p.country.length) meta.push(["归属", p.country.join("、")]);
  if (p.motivation && p.motivation.length) meta.push(["动机", p.motivation.join("；")]);
  if (p.first_seen) meta.push(["最早发现", p.first_seen]);
  return `<div class="card actor-card">
    <div class="side-h">组织档案<span class="muted" style="font-weight:400;font-size:12px">来自 ETDA</span></div>
    <div class="side-b">
      <div class="ac-name">${esc(p.name)}</div>
      ${meta.map(([k, v]) => `<div class="ac-kv"><span class="k">${k}</span><span>${esc(v)}</span></div>`).join("")}
      <div class="side-sub" style="margin-top:12px">别名 <span class="muted">${num(p.names.length)} 个，点击可查询</span></div>
      <div class="cloud">${p.names.map(n => `<a class="tag orange" href="${qlink(n)}" title="${esc(n)}">${esc(n)}</a>`).join("")}</div>
      ${p.description ? `<div class="ac-desc">${esc(p.description)}</div>` : ""}
      ${safeUrl(p.url) ? `<a class="btn round" style="margin-top:12px" href="${esc(safeUrl(p.url))}" target="_blank" rel="noopener noreferrer">ETDA 组织卡片 ↗</a>` : ""}
    </div>
  </div>`;
}

async function renderSearch(q) {
  const seq = routeSeq;
  view.innerHTML = `<div class="wrap"><div class="detail"><div class="dcol"><div class="card" style="padding:28px">${skel(6)}</div></div>
    <div class="dcol"><div class="card" style="padding:20px">${skel(4)}</div></div></div></div>`;
  const fail = msg => {
    view.innerHTML = `<div class="wrap"><div class="card" style="margin:16px 0;padding:40px 0"><div class="empty">
      <div style="font-size:40px;color:#c5cad3;margin-bottom:6px">⚠</div>${esc(msg)}
      <div style="margin-top:14px"><a class="btn" href="#/">返回首页</a></div></div></div></div>`;
  };
  if (!q.trim()) { fail("请输入要查询的 IP / 域名 / URL / 哈希 / 家族名"); return; }
  pushRecent(q.trim().slice(0, 512));
  let d;
  try { d = await api("/api/search?q=" + encodeURIComponent(q.slice(0, 512))); }
  catch (e) { fail(e.message); return; }
  if (d.error) { fail(d.error); return; }
  if (seq !== routeSeq) return;

  const isKw = d.kind === "keyword";
  const vk = isKw ? "keyword" : d.verdict;
  const word = KIND_WORD[d.kind];
  const famNames = d.families.map(f => f[0]);
  const srcNames = d.sources.map(s => s[0]);
  const portCnt = d.ports.length;

  const enrichPills = ((d.ip_enrich && d.ip_enrich.tags) || []).map(t => {
    const cls = t.kind === "threat" ? "pill enrich threat" : "pill enrich asset";
    const tip = [t.label, t.cidr, t.source].filter(Boolean).join(" · ");
    return `<span class="${cls}" title="${esc(tip)}">${esc(t.label)}</span>`;
  });
  const pills = [`<span class="pill solid ${vk}">${isKw ? "关键词检索" : V[vk].label}</span>`]
    .concat(enrichPills)
    .concat(d.families.slice(0, 6).map(([n]) => `<a class="pill line" href="${qlink(n)}" title="${esc(n)}">☣ ${esc(n)}</a>`))
    .concat(d.families.length > 6 ? [`<span class="pill more" title="${esc(d.families.slice(6).map(f => f[0]).join("、"))}">+${d.families.length - 6}</span>`] : []).join("");

  const kv = [];
  const kvItem = (k, v, tab) => kv.push(`<div><span class="k">${k}</span>${tab ? `<a class="v" role="button" tabindex="0" data-tab="${tab}">${v}</a>` : `<span class="v">${v}</span>`}</div>`);
  const samples = [...(d.related_samples || [])];
  const sampleFams = d.sample_families || famNames;
  let sampLoading = !isKw && sampleFams.length > 0 && !samples.length;
  if (d.kind === "file_hash") kvItem("哈希类型", esc(d.kind_label));
  if (d.kind === "ip") kvItem("IP", `<span class="mono">${esc(d.ip)}</span>`);
  if (d.kind === "ip" && d.geo && d.geo.label) kvItem("归属地", esc(d.geo.label));
  const enrich = d.ip_enrich || null;
  let enrichTags = (enrich && enrich.tags) || [];
  if (!enrichTags.length && (d.profile_records || []).length) {
    enrichTags = [...new Set(d.profile_records.flatMap(r => String(r.source || "").replace(/^IP画像·/, "").split("/")))]
      .filter(Boolean).map(l => ({kind: /DROP/i.test(l) ? "threat" : "asset", label: l}));
  }
  if ((d.kind === "ip" || d.kind === "url") && enrichTags.length) {
    kvItem("IP 画像", enrichTags.map(t => esc(t.label)).join(" · "));
  }
  if (d.kind === "url" && d.host) kvItem("主机", `<span class="mono">${esc(d.host)}</span>`);
  if (d.geo && d.geo.label && d.kind === "url") kvItem("主机归属地", esc(d.geo.label));
  kvItem(isKw ? "匹配记录" : "情报记录", num(d.records.length) + (d.truncated ? "+" : ""), "rec");
  if (isKw && d.family_total) kvItem("主库总量", num(d.family_total) + " 条");
  if (d.kind === "ip") kvItem("端口记录", num(portCnt), "rec");
  if (d.kind === "domain") kvItem("父域名命中", num(d.parent_domains.length), "par");
  if (d.kind === "url") kvItem("主机命中", num(d.parent_domains.length), "par");
  if (["ip", "domain", "url"].includes(d.kind)) kvItem(d.kind === "url" ? "同主机 URL" : "相关 URL", num(d.related_urls.length), "url");
  if (samples.length || famNames.length || sampLoading) kvItem("关联样本", sampLoading ? "…" : num(samples.length), "samp");
  kvItem("恶意家族", famNames.length ? esc(famNames.slice(0, 3).join("、")) : "-");
  kvItem("情报来源", srcNames.length ? esc(srcNames.slice(0, 3).join("、")) : "-");
  kvItem("安全博客", num(d.articles.length) + " 篇", "art");

  /* 情报洞察 */
  const groups = [];
  const row = (mark, t, desc) => `<div class="ins-row"><span class="t">${mark === "dia" ? '<span class="dia">◆</span>' : '<span class="dot">●</span>'} ${t}</span><span class="d">${desc}</span></div>`;
  let nDia = 0, nDot = 0;
  const add = (mark, t, desc) => { mark === "dia" ? nDia++ : nDot++; return row(mark, t, desc); };
  const g1 = [];
  if (d.report_host) g1.push(add("dot", "安全厂商 / 媒体站点", `${esc(d.report_host)} 属于安全厂商、安全媒体或 CERT 站点，库里的记录多是情报文章里的引用链接被误收为 IOC，已不按恶意处理${d.verdict_raw && d.verdict_raw !== "unknown" ? `（原判定：${esc(V[d.verdict_raw]?.label || d.verdict_raw)}）` : ""}`));
  if (!isKw && d.records.length && !d.report_host) {
    if (famNames.length) g1.push(add("dia", `${esc(famNames[0])} 相关`, `该${word}被标记为 ${esc(famNames.slice(0, 3).join("、"))} 相关的恶意${word}`));
    else g1.push(add("dia", "已知恶意指标", `该${word}已被情报库收录为威胁指标`));
  } else if (!isKw && d.article_ioc_hit) {
    const artFam = [...new Set(d.articles.flatMap(a => [...(a.malware || []), ...(a.actors || [])]))].slice(0, 3);
    g1.push(add("dia", "情报文章 IOC", `该${word}出现在 ${num(d.articles.length)} 篇安全情报文章的 IOC 列表中${artFam.length ? `，关联 ${esc(artFam.join("、"))}` : ""}（主库暂未收录）`));
  }
  if (isKw && d.records.length) g1.push(add("dia", "家族 / 关键词命中", `情报库中有 ${num(d.records.length)}${d.truncated ? "+" : ""} 条指标与“${esc(d.normalized)}”相关`));
  if (d.articles.length) g1.push(add("dot", "安全博客提及", `共有 ${num(d.articles.length)} 篇安全博客文章提及该${word}`));
  if (d.actor_profile) g1.push(add("dot", "APT 组织别名", `“${esc(d.normalized)}”是 ${esc(d.actor_profile.name)} 的别名，文章已按该组织的 ${num(d.actor_profile.names.length)} 个别名一并匹配`));
  if (g1.length) groups.push({cat: "关联情报", icon: ICON.link, rows: g1});
  const g2 = [];
  if (d.kind === "domain" && d.parent_domains.length) g2.push(add("dia", "父域名恶意", `其上级域名 ${esc(d.parent_domains.map(r => r.value).slice(0, 3).join("、"))} 被标记为恶意`));
  if (d.kind === "url" && d.parent_domains.length) g2.push(add("dia", "主机恶意", `该 URL 所在主机 ${esc(d.host)} 已被标记为恶意`));
  if (d.related_urls.length) g2.push(add("dia", "关联恶意 URL", `该${d.kind === "ip" ? " IP " : "主机"}下有 ${num(d.related_urls.length)} 条恶意 URL`));
  if (d.kind === "ip" && portCnt) g2.push(add("dia", "恶意服务端口", `记录到 ${portCnt} 个恶意服务端口：${esc(d.ports.slice(0, 12).map(p => ":" + p).join("  "))}`));
  if (samples.length && famNames.length) g2.push(add("dia", "同家族样本", `关联到 ${num(samples.length)} 个同家族文件哈希（${esc(famNames.slice(0, 3).join("、"))}）`));
  if (d.geo && d.geo.label) g2.push(add("dot", "IP 归属地", `本地 GeoIP：${esc(d.geo.label)}`));
  if (enrichTags.length) {
    const threat = enrichTags.filter(t => t.kind === "threat").map(t => t.label);
    const asset = enrichTags.filter(t => t.kind !== "threat").map(t => t.label);
    if (threat.length) g2.push(add("dia", "威胁网段", `命中 ${esc(threat.join("、"))}（未写入主 IOC 库，仅画像标签）`));
    if (asset.length) g2.push(add("dot", "网络属性", `标记为 ${esc(asset.join("、"))}——基建/出口属性，不单独等同恶意`));
  }
  if (g2.length) groups.push({cat: "关联资产", icon: ICON.target, rows: g2});
  const g3 = [];
  if (srcNames.length) g3.push(add("dot", srcNames.length > 1 ? "多源交叉验证" : "情报来源", `被 ${srcNames.length} 个情报源收录：${esc(srcNames.slice(0, 6).join("、"))}`));
  if (d.last_seen) g3.push(add("dot", "最近提及", `最近一次出现在安全博客中的时间为 ${esc(d.last_seen)}`));
  if (g3.length) groups.push({cat: "历史行为", icon: ICON.at, rows: g3});
  if (!groups.length) groups.push({cat: "研判结论", icon: ICON.card, rows: [add("dot", "暂无情报", `本地情报库未收录该${word}，也未在安全博客中发现，不代表安全，建议结合其他情报源研判`)]});

  /* 三条摘要：本地情报只按查询值本身的记录描述，父域名 / 主机的信息归到相关情报 */
  const recSrc = [...new Set(d.records.map(r => normSrc(r.source)).filter(Boolean))];
  const recFam = [...new Set(d.records.flatMap(r => r.families || []))];
  const relCnt = d.related_urls.length + d.parent_domains.length;
  const sumRows = [
    {cls: d.records.length ? "red" : "", n: "本地情报", tab: "rec", html: `<b>${num(d.records.length)}${d.truncated ? "+" : ""}</b>条情报记录${recSrc.length ? `，来自 ${esc(recSrc.slice(0, 3).join("、"))}${recSrc.length > 3 ? " 等" : ""}` : ""}${recFam.length ? `，关联恶意家族 ${esc(recFam.slice(0, 3).join("、"))}` : ""}。`},
    ...(isKw || d.kind === "file_hash" ? [] : [{cls: relCnt ? "orange" : "", n: "相关情报", tab: d.related_urls.length ? "url" : "par",
      html: `<b>${num(d.related_urls.length + d.parent_domains.length)}</b>条关联恶意情报，其中 关联 URL ${num(d.related_urls.length)} 条${d.kind === "domain" ? `、父域名 ${num(d.parent_domains.length)} 条` : d.kind === "url" ? `、主机 ${num(d.parent_domains.length)} 条` : `、端口 ${portCnt} 个`}。`}]),
    {cls: "", n: "安全博客", tab: "art", html: `${d.articles.length ? `${num(d.articles.length)} 篇安全博客文章提及该${word}` : "暂无安全博客提及"}${d.last_seen ? `，最近一次 ${esc(d.last_seen)}` : ""}。`},
  ];

  /* 详情标签页（记录 / 博客客户端翻页） */
  const tabPages = {};
  const tabs = [
    {k: "rec", label: isKw ? "匹配记录" : "情报记录", n: d.records.length, html: p => recTable(d.records, d.truncated ? (d.via_index
      ? `家族索引里共 ${num(d.family_total)} 条，这里按入库时间显示最新 ${num(d.records.length)} 条；按类型统计与样例见专题页` : true) : false, p)},
    ...(d.kind === "domain" || d.kind === "url" ? [{k: "par", label: d.kind === "url" ? "主机情报" : "父域名", n: d.parent_domains.length, html: p => recTable(d.parent_domains, false, p)}] : []),
    ...(["ip", "domain", "url"].includes(d.kind) ? [{k: "url", label: "相关 URL", n: d.related_urls.length, html: p => recTable(d.related_urls, false, p)}] : []),
    ...(d.kind === "ip" ? [{k: "port", label: "端口", n: portCnt, html: p => portTable(d, p)}] : []),
    {k: "samp", label: "关联样本", n: samples.length, html: p => samples.length ? recTable(samples, false, p)
      : `<div class="empty">${sampLoading ? "正在加载同家族样本…" : "暂无同家族样本"}</div>`},
    {k: "art", label: "安全博客", n: d.articles.length, html: p => artTable(d.articles, p)},
  ];

  /* 右栏 */
  const syntax = isKw ? `malware=="${d.normalized}"` : `${d.kind === "file_hash" ? "hash" : d.kind}=="${d.normalized}"`;
  const rel = [];
  if (d.kind === "url" && d.host) rel.push([d.host, d.parent_domains.length ? "主机（恶意）" : "查询主机"]);
  if (d.kind === "domain") {
    const labels = d.normalized.split(".");
    for (let i = 1; i < labels.length - 1; i++) {
      const p = labels.slice(i).join(".");
      rel.push([p, d.parent_domains.some(r => r.value === p) ? "父域名（恶意）" : "父域名"]);
    }
  }
  if (d.kind === "ip" && d.ports.length) d.ports.slice(0, 5).forEach(p => rel.push([`${d.ip}:${p}`, "端口"]));
  famNames.slice(0, 3).forEach(f => rel.push([f, "同家族指标"]));
  const abuseIp = d.kind === "ip" ? d.ip : (d.kind === "url" && /^\d{1,3}(\.\d{1,3}){3}$/.test(d.host || "") ? d.host : "");
  const dnsHost = d.kind === "domain" ? d.normalized : (d.kind === "url" && d.host && !abuseIp ? d.host : "");
  const profName = isKw ? (d.actor_profile ? d.actor_profile.name : (d.family_matches && d.family_matches.length ? d.normalized : "")) : "";
  const tagsHtml = (d.tags || []).map(t => `<a class="tag ${t.kind === "malware" ? "red" : "orange"}" href="${qlink(t.name)}" title="${esc(t.name)}">${t.kind === "malware" ? "☣ " : ""}${esc(t.name)}<i>${t.count}</i></a>`).join("")
    + srcNames.map((s, i) => `<span class="tag" title="情报来源：${esc(s)}">${esc(s)}<i>${d.sources[i][1]}</i></span>`).join("");

  view.innerHTML = `<div class="wrap"><div class="detail">
  <div class="dcol">
    <div class="card dhero">
      <div class="dhead">
        <div class="dact">${watchBtnHtml(d.watch_id)}${profName ? `<a class="btn round" href="${profileLink(profName)}">专题页</a>` : ""}<button class="btn round" id="csv">${ICON.export} 导出</button></div>
        <div class="dtop">
          <div class="vring ${vk}"><span class="g">${V[vk].glyph}</span><span class="l">${isKw ? "检索" : V[vk].label}</span></div>
          <div class="dmain">
            <div class="dtitle"><span class="${isKw ? "" : "mono"}" style="${isKw ? "" : "font-family:inherit"}">${esc(d.normalized)}</span><button class="cp" id="cp" title="复制">${ICON.copy}</button></div>
            <div class="dmeta">${d.last_seen ? `<span>${esc(d.last_seen)} 情报更新</span>` : ""}<span>类型：${esc(d.kind_label)}</span><span>查询用时 ${d.elapsed_ms} ms</span></div>
            <div>${pills}</div>
            <div class="kvs">${kv.join("")}</div>
            ${pivotLinks(d)}
          </div>
        </div>
      </div>
      <div class="insight">
        <div class="ins-h">${ICON.book.replace("<svg", '<svg width="18" height="18"')}情报洞察<button class="tg" id="insTg">⌄</button></div>
        <div id="insBody">
          <div class="ins-sum">包含 <span class="dia">◆</span> ${nDia} 条可疑特征，<span class="dot">●</span> ${nDot} 条重点特征</div>
          <div class="ins-box">${groups.map(g => `<div class="ins-grp"><div class="ins-cat">${g.icon}${g.cat}</div><div>${g.rows.join("")}</div></div>`).join("")}</div>
          <div class="ins-acts"><span class="ai">快捷操作</span>
            <button class="btn round" id="a1">复制“${esc(short(d.normalized))}”</button>
            <button class="btn round" id="a2">导出“${esc(short(d.normalized))}”的情报记录</button>
            <button class="btn round" id="a3">查看提及“${esc(short(d.normalized))}”的安全博客</button>
          </div>
        </div>
      </div>
    </div>
    <div class="card sums">${sumRows.map(s => `<div class="srow ${s.cls}" data-tab="${s.tab}"><span class="n">${s.n}</span><span class="c">${s.html}</span><span class="arr">›</span></div>`).join("")}</div>
    <div class="card" id="tabCard">
      <div class="tabs" id="tabs">${tabs.map((t, i) => `<button data-k="${t.k}" class="${i ? "" : "on"} ${t.n ? "" : "zero"}">${t.label}<span class="cnt">${num(t.n)}</span></button>`).join("")}</div>
      <div id="tabBody"></div>
    </div>
  </div>
  <div class="dcol dside">
    <div class="card">
      <div class="side-h">查询快速指引</div>
      <div class="side-b">
        <div class="side-sub">${ICON.target.replace("<svg", '<svg width="14" height="14"')}精确查询</div>
        <div class="code"><span>${esc(syntax)}</span><button id="cpSyn" title="复制">${ICON.copy}</button></div>
        ${rel.length ? `<div class="side-sub" style="margin-top:14px">${ICON.link.replace("<svg", '<svg width="14" height="14"')}关联查询</div>
          <div class="rel">${rel.map(([v, l]) => `<a href="${qlink(v)}" title="${esc(v)}"><span class="tbadge">${esc(l)}</span><span class="mono rv">${esc(v)}</span></a>`).join("")}</div>` : ""}
      </div>
    </div>
    <div class="card">
      <div class="side-h">情报标签</div>
      <div class="side-b"><div class="cloud">${tagsHtml || `<span class="muted">暂无标签</span>`}</div>
        <button class="darkbtn" id="cpAll">复制全部关联 IOC</button></div>
    </div>
    ${actorCard(d.actor_profile)}
    ${abuseIp ? `<div class="card" id="abuseCard"><div class="side-h">AbuseIPDB 信誉</div><div class="side-b"><span class="muted">正在查询…</span></div></div>` : ""}
    ${dnsHost ? `<div class="card" id="dnsCard"><div class="side-h">DNS 解析联动</div><div class="side-b">
      <div class="muted" style="font-size:12px;line-height:1.7">点击后由面板所在主机向本机 DNS 发起真实解析，再把解析出的 IP 逐个比对主库、IP 画像与情报文章。对仍活跃的恶意域名，这次解析可能被攻击者的权威 DNS 记录。</div>
      <button class="btn round" id="dnsBtn" style="margin-top:10px">解析 ${esc(short(dnsHost))} 的 A 记录</button><div id="dnsRes"></div></div></div>` : ""}
    <div class="card">
      <div class="side-h">研判说明</div>
      <div class="side-b legend">
        <div><i style="color:var(--red)">恶意</i>该指标本身已被情报库收录，或出现在情报文章的 IOC 列表中</div>
        <div><i style="color:var(--orange)">可疑</i>本身未收录，但父域名 / 主机 / 关联 URL 命中</div>
        <div><i style="color:#8a93a6">未知</i>本地情报库未收录，不代表安全</div>
      </div>
    </div>
    <div class="card dfill">
      <div class="side-h">最近查询</div>
      <div class="side-b">
        <div class="rq">${recentList().filter(v => v !== q).map(v => `<a href="${qlink(v)}" title="${esc(v)}"><span class="tbadge">${esc(detectKind(v) || "关键词")}</span><span class="mono rv">${esc(v)}</span></a>`).join("") || `<span class="muted">暂无其他查询记录</span>`}</div>
        <div class="side-sub" style="margin-top:14px">常用工具</div>
        <div class="qtools"><a href="#/batch"><i style="background:#2c6cf6">批</i>批量研判</a><a href="#/watch"><i style="background:#b07c00">★</i>关注列表</a><a href="#/apt"><i style="background:#d4282d">APT</i>APT / 家族</a><a href="#/intel"><i style="background:#1f7ae0">讯</i>情报动态</a></div>
      </div>
    </div>
  </div>
  </div></div>`;

  const body = $("#tabBody");
  const showTab = (k, page) => {
    const t = tabs.find(x => x.k === k) || tabs[0];
    if (page != null) tabPages[t.k] = page;
    const p = tabPages[t.k] || 1;
    $("#tabs").querySelectorAll("button").forEach(b => b.classList.toggle("on", b.dataset.k === t.k));
    body.innerHTML = t.html(p);
    bindArticles(body);
    const pages = Math.max(1, Math.ceil((t.n || 0) / TAB_PAGE));
    body.querySelectorAll(".pg[data-p]").forEach(b => b.addEventListener("click", () => {
      const np = +b.dataset.p;
      if (np >= 1 && np <= pages) showTab(t.k, np);
    }));
    const jumpIn = body.querySelector(".pg-jump input");
    if (jumpIn) jumpIn.addEventListener("keydown", e => {
      if (e.key !== "Enter") return;
      showTab(t.k, Math.min(pages, Math.max(1, parseInt(jumpIn.value, 10) || 1)));
    });
  };
  const jump = k => { showTab(k, 1); $("#tabCard").scrollIntoView({behavior: "smooth", block: "start"}); };
  $("#tabs").querySelectorAll("button").forEach(b => b.addEventListener("click", () => showTab(b.dataset.k)));
  view.querySelectorAll("[data-tab]").forEach(el => {
    el.addEventListener("click", () => jump(el.dataset.tab));
    el.addEventListener("keydown", e => { if (e.key === "Enter") jump(el.dataset.tab); });
  });
  showTab("rec");
  if (sampLoading) {
    const qs = new URLSearchParams({
      families: sampleFams.slice(0, 5).join(","),
      exclude: (d.sample_exclude || []).join(","),
    });
    api("/api/related_samples?" + qs).then(r => {
      if (seq !== routeSeq) return;
      sampLoading = false;
      const items = r.items || [];
      samples.splice(0, samples.length, ...items);
      d.related_samples = samples;
      const sampTab = tabs.find(t => t.k === "samp");
      if (sampTab) sampTab.n = samples.length;
      const btn = $("#tabs")?.querySelector('[data-k="samp"]');
      if (btn) {
        btn.classList.toggle("zero", !samples.length);
        const cnt = btn.querySelector(".cnt");
        if (cnt) cnt.textContent = num(samples.length);
      }
      const kvEl = view.querySelector('[data-tab="samp"]');
      if (kvEl) kvEl.textContent = num(samples.length);
      if ($("#tabs")?.querySelector("button.on")?.dataset.k === "samp") showTab("samp");
    }).catch(() => { sampLoading = false; });
  }
  bindWatchBtn(view.querySelector(".dact .watch-btn"), d.normalized);
  const dnsBtn = $("#dnsBtn");
  if (dnsBtn) dnsBtn.addEventListener("click", async () => {
    dnsBtn.disabled = true;
    const box = $("#dnsRes");
    box.innerHTML = `<div class="muted" style="margin-top:8px">解析中…</div>`;
    try {
      const r = await api("/api/resolve?domain=" + encodeURIComponent(dnsHost));
      if (seq !== routeSeq) return;
      if (r.error) box.innerHTML = `<div class="muted" style="margin-top:8px">${esc(r.error)}</div>`;
      else if (!r.ips.length) box.innerHTML = `<div class="muted" style="margin-top:8px">没有解析到 A 记录（${esc(r.resolved_at)}）</div>`;
      else box.innerHTML = (r.note ? `<div class="notice" style="margin:10px 0 0">${esc(r.note)}</div>` : "")
        + `<div class="muted" style="font-size:12px;margin:10px 0 4px">${esc(r.resolved_at)} 解析到 ${r.ips.length} 个 IP</div>`
        + r.ips.map(x => `<div class="dnsrow">${vtag(x.verdict)}<a class="mono" href="${qlink(x.ip)}">${esc(x.ip)}</a>
            ${x.records ? `<span class="muted">主库 ${num(x.records)} 条</span>` : ""}${x.articles ? `<span class="muted">文章 ${num(x.articles)} 篇</span>` : ""}
            <div class="dnsx">${famTags(x.families, 2)}${x.profile ? `<span class="tag">${esc(x.profile)}</span>` : ""}</div></div>`).join("");
    } catch (e) { box.innerHTML = `<div class="muted" style="margin-top:8px">${esc(e.message)}</div>`; }
    dnsBtn.disabled = false;
  });
  if (abuseIp) {
    api("/api/abuseipdb?ip=" + encodeURIComponent(abuseIp))
      .then(r => { if (seq === routeSeq) renderAbuse(r); })
      .catch(e => { if (seq === routeSeq) renderAbuse({configured: true, error: e.message}); });
  }
  $("#cp").onclick = $("#a1").onclick = () => copy(d.normalized);
  $("#cpSyn").onclick = () => copy(syntax);
  $("#csv").onclick = $("#a2").onclick = () => exportCsv(d);
  $("#a3").onclick = () => jump("art");
  $("#insTg").onclick = () => { const b = $("#insBody"); const hide = b.style.display !== "none"; b.style.display = hide ? "none" : ""; $("#insTg").classList.toggle("closed", hide); };
  $("#cpAll").onclick = () => {
    const vals = [...new Set([...d.records, ...d.parent_domains, ...d.related_urls, ...samples].map(r => r.value))];
    if (!vals.length) { toast("没有可复制的 IOC"); return; }
    copy(vals.join("\n"));
  };
}

function short(s) { return s.length > 28 ? s.slice(0, 26) + "…" : s; }
function normSrc(s) {
  let first = String(s || "").split("|")[0].split(", ")[0].trim();
  if (/^https?:\/\//i.test(first)) { try { first = new URL(first).hostname; } catch (e) {} }
  return first.replace(/^www\./, "");
}

function srcCell(s) {
  if (!s) return "";
  const parts = String(s).split(/\s*[|;]\s*|,\s+/).map(x => x.trim()).filter(Boolean);
  const more = parts.length > 1 ? `<span class="tag" title="${esc(parts.slice(1).join("、"))}">+${parts.length - 1}</span>` : "";
  return srcOne(parts[0] || "", s) + more;
}
function srcOne(first, s) {
  if (/^https?:\/\//i.test(first)) {
    let host = first;
    try { host = new URL(first).hostname.replace(/^www\./, ""); } catch (e) {}
    return `<a class="tag blue" href="${esc(first)}" target="_blank" rel="noopener noreferrer" title="${esc(s)}">${esc(host)} ↗</a>`;
  }
  return `<span class="tag blue" title="${esc(s)}">${esc(first.length > 40 ? first.slice(0, 40) + "…" : first)}</span>`;
}

function famCell(r) {
  const fams = r.families || (r.malware ? [r.malware] : []);
  if (!fams.length) return "";
  const shown = fams.slice(0, 3).map(f => `<a class="tag red" href="${qlink(f)}" title="${esc(f)}">☣ ${esc(f)}</a>`).join("");
  return shown + (fams.length > 3 ? `<span class="tag" title="${esc(fams.slice(3).join("、"))}">+${fams.length - 3}</span>` : "");
}

const TAB_PAGE = 20;

function tabPager(total, page) {
  const pages = Math.max(1, Math.ceil(total / TAB_PAGE));
  page = Math.min(Math.max(1, page || 1), pages);
  if (pages <= 1) return {page, pages, html: ""};
  return {
    page, pages,
    html: `<div class="pager"><span class="muted">共 ${num(total)} 条 · 第 ${page} / ${pages} 页</span>
      <div class="pgs">${pager(page, pages)}</div>
      <span class="pg-jump">跳至 <input type="number" min="1" max="${pages}" value="${page}"> 页</span></div>`,
  };
}

function recTable(rows, truncated, page) {
  if (!rows?.length) return `<div class="empty">暂无记录</div>`;
  const pg = tabPager(rows.length, page);
  const slice = rows.slice((pg.page - 1) * TAB_PAGE, pg.page * TAB_PAGE);
  const hasIp = rows.some(r => r.ip_only && r.ip_only !== r.value);
  return `<div class="tbl-wrap"><table class="rtbl"><colgroup><col class="c-type"><col>${hasIp ? `<col class="c-ip">` : ""}<col class="c-src"><col class="c-fam"></colgroup>
    <thead><tr><th>类型</th><th>指标</th>${hasIp ? "<th>IP</th>" : ""}<th>情报来源</th><th>恶意家族</th></tr></thead><tbody>
    ${slice.map(r => `<tr><td><span class="tbadge t-${esc(r.type)}">${esc(TYPE_LABEL[r.type] || r.type)}</span></td>
      <td class="val"><a href="${qlink(r.value)}">${esc(r.value)}</a></td>
      ${hasIp ? `<td class="mono">${esc(r.ip_only || "")}</td>` : ""}<td class="cell-src">${srcCell(r.source)}</td>
      <td class="cell-fam">${famCell(r)}</td></tr>`).join("")}
  </tbody></table></div>${pg.html}${truncated ? `<div class="notice">${typeof truncated === "string" ? esc(truncated) : `结果较多，仅显示前 ${rows.length} 条，请输入更精确的关键词`}</div>` : ""}`;
}

function artTable(articles, page) {
  if (!articles?.length) return `<div class="empty">暂无安全博客提及</div>`;
  const pg = tabPager(articles.length, page);
  const slice = articles.slice((pg.page - 1) * TAB_PAGE, pg.page * TAB_PAGE);
  return `<div class="card-b">${slice.map(articleItem).join("")}</div>${pg.html}`;
}

function portTable(d, page) {
  const rows = d.records.filter(r => r.type === "ip" && r.value.includes(":"));
  if (!rows.length) return `<div class="empty">暂无端口记录</div>`;
  return recTable(rows, false, page);
}

function exportCsv(d) {
  const rows = [...d.records, ...d.parent_domains, ...d.related_urls, ...(d.related_samples || [])];
  if (!rows.length) { toast("没有可导出的记录"); return; }
  const cell = s => `"${String(s ?? "").replace(/"/g, '""')}"`;
  const csv = "\ufeff" + ["type,value,ip_only,source,malware",
    ...rows.map(r => [r.type, r.value, r.ip_only, r.source, r.malware].map(cell).join(","))].join("\r\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], {type: "text/csv"}));
  a.download = "ioc_" + d.normalized.replace(/[^\w.-]+/g, "_").slice(0, 60) + ".csv";
  a.click();
}

/* ================= 文章弹窗 ================= */
async function openArticle(id) {
  const mask = $("#mask"), modal = $("#modal");
  modal.innerHTML = `<div class="modal-b">${skel(6)}</div>`;
  mask.classList.add("show");
  let a;
  try { a = await api("/api/article/" + id); } catch (e) { modal.innerHTML = `<div class="modal-b"><div class="empty">${esc(e.message)}</div></div>`; return; }
  const groups = Object.entries(a.iocs || {}).filter(([, v]) => v.length);
  modal.innerHTML = `<div class="modal-h"><div style="min-width:0">
      <div class="muted" style="font-size:12px;margin-bottom:6px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">${catBadges(a, 6)}<b style="color:var(--primary)">${esc(a.source)}</b> · ${esc(a.date)}</div>
      <h2>${esc(a.title)}</h2></div><button class="x" id="mx">×</button></div>
    <div class="modal-b">
      <div>${tagList(a, 50)}</div>
      ${a.summary ? `<p style="color:var(--sub)">${esc(a.summary)}</p>` : ""}
      ${safeUrl(a.url) ? `<p><a href="${esc(safeUrl(a.url))}" target="_blank" rel="noopener noreferrer">查看原文 ↗</a></p>` : ""}
      ${groups.length ? groups.map(([t, vals]) => `<div class="ioc-grp"><h4><span class="tbadge t-${esc(t)}">${esc(TYPE_LABEL[t] || t)}</span><span class="muted">${vals.length} 个</span></h4>
        <div class="ioc-list">${vals.map(v => `<a href="${qlink(v)}">${esc(v)}</a>`).join("")}</div></div>`).join("")
        : `<div class="empty">该文章未提取到 IOC</div>`}
    </div>`;
  $("#mx").onclick = closeModal;
  modal.querySelectorAll("a[href^='#/']").forEach(x => x.addEventListener("click", closeModal));
}
/* ================= 暗网勒索 ================= */
const COUNTRY = {US: "美国", CN: "中国", GB: "英国", UK: "英国", DE: "德国", FR: "法国", IT: "意大利", ES: "西班牙", CA: "加拿大",
  AU: "澳大利亚", JP: "日本", KR: "韩国", IN: "印度", BR: "巴西", MX: "墨西哥", NL: "荷兰", CH: "瑞士", BE: "比利时", SE: "瑞典",
  NO: "挪威", DK: "丹麦", FI: "芬兰", PL: "波兰", AT: "奥地利", PT: "葡萄牙", IE: "爱尔兰", IL: "以色列", TR: "土耳其", RU: "俄罗斯",
  UA: "乌克兰", SG: "新加坡", MY: "马来西亚", TH: "泰国", ID: "印度尼西亚", VN: "越南", PH: "菲律宾", TW: "中国台湾", HK: "中国香港",
  AE: "阿联酋", SA: "沙特", EG: "埃及", ZA: "南非", NG: "尼日利亚", AR: "阿根廷", CL: "智利", CO: "哥伦比亚", PE: "秘鲁", NZ: "新西兰"};
const STATUS = {listed: "已公布于泄露站", published: "数据已公开", leaked: "数据已泄露"};
const country = c => c ? (COUNTRY[c.toUpperCase()] ? `${COUNTRY[c.toUpperCase()]} (${c})` : c) : "未知";
const SECTOR = {
  "manufacturing": "制造业", "technology": "科技 / IT", "professional services": "专业服务", "healthcare": "医疗健康",
  "financial services": "金融服务", "education": "教育", "retail & e-commerce": "零售电商", "transportation": "交通物流",
  "energy & utilities": "能源公用事业", "government & defense": "政府 / 国防", "agriculture and food production": "农业食品",
  "construction": "建筑", "legal": "法律", "telecommunications": "电信", "media & entertainment": "媒体娱乐",
  "hospitality": "酒店餐饮", "real estate": "房地产", "non-profit": "非营利组织", "insurance": "保险",
  "pharmaceuticals": "医药", "automotive": "汽车", "aerospace": "航空航天", "chemicals": "化工", "logistics": "物流",
  "consumer services": "消费服务", "business services": "商业服务", "other": "其他", "not found": "未知",
};
const sectorName = s => s ? (SECTOR[String(s).toLowerCase()] || s) : "未知";
const sectorTag = s => s ? `<span title="${esc(s)}">${esc(sectorName(s))}</span>` : `<span class="muted">未知</span>`;

function darkRow(d) {
  return `<div class="dw click" data-did="${d.id}" role="button" tabindex="0" title="查看事件详情">
    <span class="g">${esc(d.group || "未知")}</span>
    <span class="t" title="${esc(d.victim)}">${esc(d.victim)}${d.sector ? ` <span class="muted">· ${esc(sectorName(d.sector))}</span>` : ""}</span>
    <span class="muted">${esc(country(d.country))} · ${esc(d.date)}</span></div>`;
}
function victimTable(list) {
  return `<div class="dk-list"><table class="vtbl"><thead><tr><th>受害方</th><th style="width:22%">行业</th><th style="width:18%">国家 / 地区</th><th style="width:110px">公布时间</th></tr></thead><tbody>
    ${list.map(v => `<tr class="click" data-did="${v.id}" role="button" tabindex="0" title="查看事件详情">
      <td class="vname">${esc(v.victim)}</td><td>${sectorTag(v.sector)}</td><td>${esc(country(v.country))}</td><td class="muted">${esc(v.date)}</td></tr>`).join("")}
  </tbody></table></div>`;
}
function bindDark(root) {
  root.querySelectorAll("[data-did]").forEach(el => {
    el.addEventListener("click", () => openDark(+el.dataset.did));
    el.addEventListener("keydown", e => { if (e.key === "Enter") openDark(+el.dataset.did); });
  });
}

async function openDark(id) {
  const mask = $("#mask"), modal = $("#modal");
  modal.innerHTML = `<div class="modal-b">${skel(6)}</div>`;
  mask.classList.add("show");
  let r;
  try { r = await api("/api/darkweb/" + id); } catch (e) { modal.innerHTML = `<div class="modal-b"><div class="empty">${esc(e.message)}</div></div>`; return; }
  const d = r.item;
  const victimIsDomain = RE.domain.test(d.victim) && !/\*/.test(d.victim);
  const masked = /\*{3,}/.test(d.victim);
  const groupPage = d.group ? `https://www.ransomware.live/group/${encodeURIComponent(d.group.toLowerCase())}` : "";
  const kv = [
    ["勒索团伙", d.group ? `<a href="${dkHash({group: d.group})}" class="dk-link" title="查看该团伙全部事件">${esc(d.group)}</a>` : "未知"],
    ["受害方", masked ? `${esc(d.victim)} <span class="muted">（泄露站已打码）</span>`
      : `<a class="dk-link" href="${qlink(d.victim)}" title="在情报库中查询">${esc(d.victim)}</a>${victimIsDomain
        ? ` <a class="dk-ext" href="https://${esc(d.victim)}" target="_blank" rel="noopener noreferrer nofollow" title="打开受害方网站">访问 ↗</a>` : ""}`],
    ["国家 / 地区", d.country ? `<a class="dk-link" href="${dkHash({country: d.country})}" title="查看同国家事件">${esc(country(d.country))}</a>` : "未知"],
    ["行业", d.sector ? `<a class="dk-link" href="${dkHash({sector: d.sector})}" title="查看同行业事件（${esc(d.sector)}）">${esc(sectorName(d.sector))}</a>` : "未知"],
    ["状态", esc(STATUS[d.status] || d.status || "未知")],
    ["公布时间", `${esc(d.time || d.date)} <span class="muted" title="泄露站发布、被暗网监控发现的时间，不是攻击发生时间">ⓘ</span>`],
  ];
  if (d.domain) kv.push(["受害方网站", `<a class="dk-link" href="${qlink(d.domain)}" title="在情报库中查询">${esc(d.domain)}</a>
    <a class="dk-ext" href="https://${esc(d.domain.replace(/^https?:\/\//, ""))}" target="_blank" rel="noopener noreferrer nofollow">访问 ↗</a>`]);
  if (d.attack_date) kv.push(["攻击时间", `${esc(d.attack_date)} <span class="muted" title="泄露站或 ransomware.live 给出的估计攻击时间">（估计）</span>`]);
  if (d.data_size) kv.push(["泄露数据量", esc(d.data_size)]);
  if (d.ransom) kv.push(["赎金", esc(d.ransom)]);
  kv.push(["数据来源", esc((d.sources || []).join(" / ") || "—")]);
  const aiDesc = /^\s*\[ai generated\]/i.test(d.description || "");
  const desc = (d.description || "").replace(/^\s*\[ai generated\]\s*/i, "");
  const stat = (list, key, fn) => list.map(([n, c]) => `<a class="tag" href="${dkHash({group: d.group, [key]: n})}" title="查看该团伙在此${key === "country" ? "国家" : "行业"}的事件">${esc(fn ? fn(n) : n)}<i>${c}</i></a>`).join("") || `<span class="muted">—</span>`;
  modal.innerHTML = `<div class="modal-h"><div style="min-width:0">
      <div style="margin-bottom:6px"><span class="pill solid">勒索事件</span>${d.group ? `<span class="pill line">☣ ${esc(d.group)}</span>` : ""}</div>
      <h2>${esc(d.victim)} 被 ${esc(d.group || "未知团伙")} 勒索团伙公布</h2></div><button class="x" id="mx" aria-label="关闭">×</button></div>
    <div class="modal-b">
      <div class="dk-kv">${kv.map(([k, v]) => `<div><span class="k">${k}</span><span class="v">${v}</span></div>`).join("")}</div>
      ${desc ? `<div class="dk-desc"><span class="k">泄露站描述</span>${esc(desc)}${aiDesc ? ` <span class="muted">（ransomware.live AI 生成，仅供参考）</span>` : ""}</div>` : ""}
      <div class="ins-acts" style="margin-top:14px">
        ${d.group ? `<a class="btn round" href="${dkHash({group: d.group})}">查看该团伙全部事件</a>` : ""}
        ${d.group ? `<a class="btn round" href="${qlink(d.group)}">在情报库中查询“${esc(d.group)}”</a>` : ""}
        ${!masked ? `<a class="btn round" href="${qlink(d.victim)}">查询受害方“${esc(short(d.victim))}”</a>` : ""}
        ${safeUrl(d.rl_url) ? `<a class="btn round" href="${esc(safeUrl(d.rl_url))}" target="_blank" rel="noopener noreferrer">ransomware.live 事件页 ↗</a>` : ""}
        ${safeUrl(d.screenshot) ? `<a class="btn round" href="${esc(safeUrl(d.screenshot))}" target="_blank" rel="noopener noreferrer">泄露站截图 ↗</a>` : ""}
        ${safeUrl(d.press) ? `<a class="btn round" href="${esc(safeUrl(d.press))}" target="_blank" rel="noopener noreferrer">媒体报道 ↗</a>` : ""}
        ${safeUrl(d.tc_url) ? `<a class="btn round" href="${esc(safeUrl(d.tc_url))}" target="_blank" rel="noopener noreferrer">ThreatCluster 原文 ↗</a>` : ""}
        <button class="btn round" id="dkCopy">复制事件信息</button>
      </div>
      ${groupProfile(r.group_profile, d.group, groupPage)}
      <div class="dk-sec"><h4>${esc(d.group || "该团伙")} 本地统计</h4>
        <div class="dk-note">统计范围：本地采集的暗网监控数据（ransomware.live / ThreatCluster，${esc(r.coverage_from || "—")} ~ ${esc(r.coverage_to || "—")}），不代表该团伙的全部历史</div>
        <div class="dk-kv">
          <div><span class="k">受害者数</span><span class="v">${num(r.group_total)} 个（含本条）</span></div>
          <div><span class="k">首次 / 最近</span><span class="v">${esc(r.first_seen || "—")} ~ ${esc(r.last_seen || "—")}</span></div>
        </div>
        <div style="margin-top:8px"><span class="muted" style="font-size:12px;margin-right:6px">受害国家</span>${stat(r.top_countries, "country", country)}</div>
        <div><span class="muted" style="font-size:12px;margin-right:6px">受害行业</span>${stat(r.top_sectors, "sector", sectorName)}</div>
      </div>
      <div class="dk-sec"><h4>该团伙其他受害者 <span class="muted">${r.group_total > 1 ? `${num(r.group_total - 1)} 个，按公布时间倒序${r.group_total - 1 > r.victims.length ? `，显示最近 ${r.victims.length} 个` : ""}` : ""}</span>
          ${r.group_total - 1 > r.victims.length ? `<a class="btn" style="margin-left:8px" href="${dkHash({group: d.group})}">查看全部</a>` : ""}</h4>
        ${r.victims.length ? victimTable(r.victims) : `<div class="empty" style="padding:12px 0">本地数据中暂无该团伙的其他受害者</div>`}</div>
      <div class="dk-sec"><h4>相关安全博客 <span class="muted">${r.articles.length ? `${r.articles.length} 篇，标题提及的排在前面` : ""}</span></h4>
        ${r.articles.length ? r.articles.map(a => articleItem(a).replace('<div class="meta">',
          `<div class="meta"><span class="mention ${a.mention === "title" ? "t" : "b"}" title="${a.mention === "title" ? "文章标题直接提到该团伙" : "文章被打上该团伙标签，可能只是正文中顺带提及"}">${a.mention === "title" ? "标题提及" : "正文提及"}</span>`)).join("")
          : `<div class="empty" style="padding:12px 0">暂无安全博客提及该团伙</div>`}</div>
    </div>`;
  $("#mx").onclick = closeModal;
  $("#dkCopy").onclick = () => copy([
    `勒索团伙：${d.group || "未知"}`, `受害方：${d.victim}`, d.domain ? `受害方网站：${d.domain}` : "",
    `国家/地区：${country(d.country)}`, `行业：${sectorName(d.sector)}`,
    `状态：${STATUS[d.status] || d.status || "未知"}`, `公布时间：${d.time || d.date}`,
    d.attack_date ? `攻击时间（估计）：${d.attack_date}` : "", d.data_size ? `泄露数据量：${d.data_size}` : "",
    `来源：${d.source_url}`,
  ].filter(Boolean).join("\n"));
  modal.querySelectorAll("[data-copy]").forEach(el => el.addEventListener("click", () => copy(el.dataset.copy)));
  bindDark(modal);
  bindArticles(modal);
  modal.querySelectorAll("a[href^='#/']").forEach(x => x.addEventListener("click", closeModal));
  $("#mask").scrollTop = 0;
}

const TACTIC_CN = {"Reconnaissance": "侦察", "Resource Development": "资源开发", "Initial Access": "初始访问", "Execution": "执行",
  "Persistence": "持久化", "Privilege Escalation": "权限提升", "Defense Evasion": "防御规避", "Credential Access": "凭据访问",
  "Discovery": "发现", "Lateral Movement": "横向移动", "Collection": "收集", "Command and Control": "命令与控制",
  "Exfiltration": "数据外传", "Impact": "影响"};
const TOOLCAT_CN = {CredentialTheft: "凭据窃取", DefenseEvasion: "防御规避", DiscoveryEnum: "侦察发现", Exfiltration: "数据外传",
  LOLBAS: "系统自带工具", Networking: "网络 / 隧道", Offsec: "攻击框架", "RMM-Tools": "远程管理工具", RMMTools: "远程管理工具",
  Archive: "压缩打包", Archiving: "压缩打包", Vulnerabilities: "利用漏洞", Encryption: "加密"};

function groupProfile(p, group, groupPage) {
  if (!p || !p.name) {
    return `<div class="dk-sec"><h4>团伙档案</h4><div class="empty" style="padding:10px 0">ransomware.live 暂无该团伙档案${groupPage ? `，可尝试 <a href="${esc(groupPage)}" target="_blank" rel="noopener noreferrer">在线查看 ↗</a>` : ""}</div></div>`;
  }
  const online = p.locations.filter(l => l.available).length;
  const tools = Object.entries(p.tools || {}).filter(([, v]) => v.length);
  const kv = [
    p.altname ? ["别名", esc(p.altname)] : null,
    p.added_date ? ["首次收录", esc(p.added_date)] : null,
    ["泄露站", p.locations.length ? `${online} 个在线 / 共 ${p.locations.length} 个` : "—"],
    ["ATT&CK", p.ttps.length ? `${p.ttps.length} 个战术，${p.ttps.reduce((n, t) => n + t.techniques.length, 0)} 项技术` : "—"],
  ].filter(Boolean);
  return `<div class="dk-sec gp"><h4>${esc(p.name)} 团伙档案 <span class="muted">来自 ransomware.live</span>
      ${groupPage ? `<a class="btn" style="margin-left:auto" href="${esc(groupPage)}" target="_blank" rel="noopener noreferrer">完整档案 ↗</a>` : ""}</h4>
    ${p.description ? `<p class="gp-desc">${esc(p.description)}</p>` : ""}
    <div class="dk-kv">${kv.map(([k, v]) => `<div><span class="k">${k}</span><span class="v">${v}</span></div>`).join("")}</div>
    ${tools.length ? `<div class="gp-row"><span class="lbl">常用工具</span><div>${tools.map(([cat, names]) =>
      `<div class="gp-tools"><b>${esc(TOOLCAT_CN[cat] || cat)}</b>${names.map(n => `<span class="tag">${esc(n)}</span>`).join("")}</div>`).join("")}</div></div>` : ""}
    ${p.ttps.length ? `<div class="gp-row"><span class="lbl">ATT&amp;CK</span><div class="gp-ttps">${p.ttps.map(t => `<details>
      <summary><b>${esc(TACTIC_CN[t.tactic] || t.tactic)}</b> <span class="muted">${esc(t.tactic)} · ${t.techniques.length}</span></summary>
      <ul>${t.techniques.map(x => `<li>${/^T\d{4}(\.\d{3})?$/.test(x.id) ? `<a href="https://attack.mitre.org/techniques/${x.id.replace(".", "/")}/" target="_blank" rel="noopener noreferrer" class="mono">${x.id}</a>` : `<span class="mono">${esc(x.id)}</span>`}
        ${esc(x.name)}${x.details ? `<div class="muted">${esc(x.details)}</div>` : ""}</li>`).join("")}</ul></details>`).join("")}</div></div>` : ""}
    ${p.locations.length ? `<div class="gp-row"><span class="lbl">泄露站地址</span><div class="gp-locs">${p.locations.map(l => `<div>
      <i class="st ${l.available ? "on" : ""}" title="${l.available ? "最近一次检测在线" : "最近一次检测离线"}"></i>
      <span class="tbadge">${esc(l.type || "站点")}</span><span class="mono loc" title="点击复制（Tor 地址，请勿在办公网络直接访问）" data-copy="${esc(l.fqdn)}">${esc(l.fqdn)}</span>
      ${l.title ? `<span class="muted">${esc(l.title)}</span>` : ""}</div>`).join("")}</div></div>` : ""}
  </div>`;
}

const DK_SIZES = [30, 50, 100];
function dkHash(f) {
  const p = new URLSearchParams();
  for (const k of ["group", "country", "sector"]) if (f[k]) p.set(k, f[k]);
  if (f.page > 1) p.set("page", f.page);
  if (f.size && f.size !== DK_SIZES[0]) p.set("size", f.size);
  const s = p.toString();
  return "#/darkweb" + (s ? "?" + s : "");
}

async function renderDarkweb(params) {
  const f = {
    group: (params.get("group") || "").slice(0, 80),
    country: (params.get("country") || "").slice(0, 8),
    sector: (params.get("sector") || "").slice(0, 60),
  };
  const page = Math.max(1, parseInt(params.get("page") || "1", 10) || 1);
  const size = DK_SIZES.includes(+params.get("size")) ? +params.get("size") : DK_SIZES[0];
  const nav = patch => dkHash({...f, size, page: 1, ...patch});
  const active = Object.entries(f).filter(([, v]) => v);
  const LBL = {group: "团伙", country: "国家", sector: "行业"};
  view.innerHTML = `<div class="wrap" style="margin:16px auto 36px">
    <div class="card"><div class="card-h"><h3>暗网勒索动态</h3><span class="muted" id="dkTotal"></span>
      ${active.map(([k, v]) => `<a class="tag ${k === "group" ? "red" : "blue"}" href="${nav({[k]: ""})}" title="取消该筛选">${LBL[k]}：${esc(k === "country" ? country(v) : k === "sector" ? sectorName(v) : v)} ×</a>`).join("")}
      <div class="r">${active.length ? `<a class="btn" href="${dkHash({size})}">清除全部筛选</a>` : ""}
        <span class="muted" style="font-size:12px">每页</span>
        <select id="dkSize" class="sel">${DK_SIZES.map(n => `<option value="${n}" ${n === size ? "selected" : ""}>${n} 条</option>`).join("")}</select></div></div>
      <div class="card-b">
        <div class="dk-filter"><span class="lbl">活跃团伙</span><div class="hot" id="dkGroups"></div></div>
        <div class="dk-filter"><span class="lbl">受害国家</span><div class="hot" id="dkCountries"></div></div>
        <div class="dk-filter"><span class="lbl">受害行业</span><div class="hot" id="dkSectors"></div></div>
      </div>
      <div id="dkList">${skel(10)}</div>
      <div class="pager" id="dkPager"></div></div></div>`;
  $("#dkSize").addEventListener("change", e => { location.hash = nav({size: +e.target.value}); });

  const seq = routeSeq;
  const qs = new URLSearchParams({limit: size, offset: (page - 1) * size});
  for (const [k, v] of active) qs.set(k, v);
  let d;
  try { d = await api("/api/darkweb?" + qs.toString()); }
  catch (e) { if (seq === routeSeq) $("#dkList").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  if (seq !== routeSeq) return;
  const pages = Math.max(1, Math.ceil(d.total / size));
  if (page > pages && d.total) { location.hash = dkHash({...f, size, page: pages}); return; }

  const chips = (list, key, fn) => list.map(x => {
    const on = (f[key] || "").toLowerCase() === x.name.toLowerCase();
    return `<a class="tag ${on ? "red" : ""}" href="${nav({[key]: on ? "" : x.name})}">${esc(fn ? fn(x.name) : x.name)}<i>${x.count}</i></a>`;
  }).join("");
  $("#dkGroups").innerHTML = chips(d.groups, "group");
  $("#dkCountries").innerHTML = chips(d.countries, "country", country);
  $("#dkSectors").innerHTML = chips(d.sectors, "sector", sectorName);
  $("#dkTotal").textContent = `共 ${num(d.total)} 起 · 第 ${page} / ${pages} 页`;

  let html = "", last = null;
  for (const x of d.items) {
    if (x.date !== last) { html += `<div class="dhdr">${esc(x.date || "未知日期")}</div>`; last = x.date; }
    html += darkRow(x);
  }
  $("#dkList").innerHTML = html ? `<div class="dk-rows">${html}</div>` : `<div class="empty" style="padding:50px 0">没有符合条件的事件</div>`;
  bindDark($("#dkList"));

  const pg = $("#dkPager");
  pg.innerHTML = pages > 1 ? `<span class="muted">共 ${num(d.total)} 起</span><div class="pgs">${pager(page, pages)}</div>
    <span class="pg-jump">跳至 <input id="dkPgIn" type="number" min="1" max="${pages}" value="${page}"> 页</span>` : "";
  pg.querySelectorAll(".pg[data-p]").forEach(b => b.addEventListener("click", () => {
    const p = +b.dataset.p;
    if (p >= 1 && p <= pages) location.hash = dkHash({...f, size, page: p});
  }));
  const jump = $("#dkPgIn");
  if (jump) jump.addEventListener("keydown", e => {
    if (e.key !== "Enter") return;
    location.hash = dkHash({...f, size, page: Math.min(pages, Math.max(1, parseInt(jump.value, 10) || 1))});
  });
}

function closeModal() { $("#mask").classList.remove("show"); }
$("#mask").addEventListener("click", e => { if (e.target.id === "mask") closeModal(); });
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

/* ================= 公共小工具 ================= */
const VERDICT_TXT = {malicious: "恶意", suspicious: "可疑", unknown: "未知", error: "超时"};
function vtag(v) { return `<span class="vtag ${esc(v)}">${esc(VERDICT_TXT[v] || v)}</span>`; }
const csvCell = s => `"${String(s ?? "").replace(/"/g, '""')}"`;
function downloadText(name, text, type = "text/plain") {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], {type}));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
const profileLink = n => "#/profile?name=" + encodeURIComponent(n);
function famTags(list, max = 3) {
  const l = (list || []).filter(Boolean);
  return l.slice(0, max).map(f => `<a class="tag red" href="${qlink(f)}" title="${esc(f)}">☣ ${esc(f)}</a>`).join("")
    + (l.length > max ? `<span class="tag" title="${esc(l.slice(max).join("、"))}">+${l.length - max}</span>` : "");
}

/* ================= 关注 ================= */
function setWatchBadge(n) {
  const b = $("#watchBadge");
  if (!b) return;
  b.textContent = n ? String(n) : "";
  b.classList.toggle("show", !!n);
}
async function refreshWatchBadge() {
  try {
    const r = await fetch("/api/watch", {credentials: "same-origin", headers: {"Accept": "application/json"}});
    if (r.ok) setWatchBadge((await r.json()).total_new || 0);
  } catch (e) {}
}
function watchBtnHtml(id) {
  return `<button class="btn round watch-btn ${id ? "on" : ""}" data-wid="${esc(id || "")}">${id ? "★ 已关注" : "☆ 关注"}</button>`;
}
function bindWatchBtn(btn, value) {
  if (!btn) return;
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      if (btn.dataset.wid) {
        await api("/api/watch/" + encodeURIComponent(btn.dataset.wid), {method: "DELETE"});
        btn.dataset.wid = "";
        toast("已取消关注");
      } else {
        const r = await api("/api/watch", {method: "POST", body: {value}});
        btn.dataset.wid = r.item.id;
        toast(r.exists ? "已在关注列表中" : "已关注：run_all 后有新 IOC 或新文章会提醒");
      }
      btn.classList.toggle("on", !!btn.dataset.wid);
      btn.textContent = btn.dataset.wid ? "★ 已关注" : "☆ 关注";
    } catch (e) { toast(e.message); }
    btn.disabled = false;
  });
}

async function renderWatch() {
  view.innerHTML = `
  <div class="ihead"><div class="wrap"><div class="ihead-in"><div><h1>关注列表</h1>
    <p>关注 IP / 域名 / URL / 哈希 / 家族 / APT 组织；每次 run_all 之后，新入库的 IOC 和新发布的情报文章命中关注项会在这里和顶栏提醒</p></div>
    <form class="ifilter wadd" id="wAdd" autocomplete="off">
      <input name="value" maxlength="512" placeholder="添加关注：IP / 域名 / URL / 哈希 / 家族名 / APT 组织" aria-label="添加关注">
      <input name="note" maxlength="200" placeholder="备注（可选）" class="wnote" aria-label="备注">
      <button type="submit">＋</button>
    </form></div></div></div>
  <div class="wrap page-body"><div class="card">
    <div class="card-h"><h3>关注项</h3><span class="muted" id="wCount"></span><div class="r"><button class="btn" id="wAckAll">全部标记已读</button></div></div>
    <div id="wList">${skel(6)}</div>
  </div></div>`;
  const seq = routeSeq;
  $("#wAdd").addEventListener("submit", async e => {
    e.preventDefault();
    const value = e.target.value.value.trim(), note = e.target.note.value.trim();
    if (!value) return;
    try {
      const r = await api("/api/watch", {method: "POST", body: {value, note}});
      toast(r.exists ? "已在关注列表中" : "已添加关注");
      renderWatch();
    } catch (err) { toast(err.message); }
  });
  $("#wAckAll").onclick = async () => {
    try { await api("/api/watch/all/ack", {method: "POST"}); renderWatch(); } catch (err) { toast(err.message); }
  };
  let d;
  try { d = await api("/api/watch"); } catch (e) { if (seq === routeSeq) $("#wList").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  if (seq !== routeSeq) return;
  setWatchBadge(d.total_new);
  $("#wCount").textContent = `${num(d.total)} 项，${num(d.total_new)} 项有新命中`;
  if (!d.items.length) { $("#wList").innerHTML = `<div class="empty" style="padding:60px 0">还没有关注项。可在上方添加，或在研判结果页 / 专题页点「☆ 关注」</div>`; return; }
  const kindLabel = k => k === "keyword" ? "家族 / 组织" : (TYPE_LABEL[k] || k);
  $("#wList").innerHTML = d.items.map(it => {
    const added = new Date((it.added_ts || 0) * 1000).toLocaleString("zh-CN", {hour12: false});
    const acked = new Date((it.ack_ts || 0) * 1000).toLocaleString("zh-CN", {hour12: false});
    const detail = it.new_total ? `<div class="wdetail">
        ${it.new_ioc_count ? `<div class="side-sub">新入库 IOC ${num(it.new_ioc_count)} 条${it.new_ioc_count > it.new_iocs.length ? `（显示前 ${it.new_iocs.length} 条）` : ""}</div>
          ${recTable(it.new_iocs.map(r => ({...r, families: (r.malware || "").split(/\s*[;|]\s*|,\s+/).filter(Boolean)})), false, 1)}` : ""}
        ${it.new_article_count ? `<div class="side-sub" style="margin-top:10px">新情报文章 ${num(it.new_article_count)} 篇</div>
          <div class="card-b">${it.new_articles.map(articleItem).join("")}</div>` : ""}
      </div>` : "";
    return `<div class="witem ${it.new_total ? "has-new" : ""}">
      <div class="whead">
        <span class="tbadge t-${esc(it.kind)}">${esc(kindLabel(it.kind))}</span>
        <a class="wval mono" href="${it.kind === "keyword" ? profileLink(it.value) : qlink(it.value)}">${esc(it.value)}</a>
        ${it.label && it.label.toLowerCase() !== it.value.toLowerCase() ? `<span class="tag orange">${esc(it.label)}</span>` : ""}
        ${it.note ? `<span class="muted wn">${esc(it.note)}</span>` : ""}
        ${it.new_ioc_count ? `<span class="wnew">新 IOC ${num(it.new_ioc_count)}</span>` : ""}
        ${it.new_article_count ? `<span class="wnew blue">新文章 ${num(it.new_article_count)}</span>` : ""}
        <span class="wmeta muted" title="上次已读：${esc(acked)}">关注于 ${esc(added)}</span>
        <span class="wact">
          <a class="btn" href="${qlink(it.value)}">研判</a>
          ${it.kind === "keyword" ? `<a class="btn" href="${profileLink(it.value)}">专题</a>` : ""}
          ${it.new_total ? `<button class="btn" data-ack="${esc(it.id)}">标记已读</button>` : ""}
          <button class="btn danger" data-del="${esc(it.id)}">删除</button>
        </span>
      </div>${detail}</div>`;
  }).join("");
  bindArticles($("#wList"));
  $("#wList").querySelectorAll("[data-ack]").forEach(b => b.addEventListener("click", async () => {
    try { await api("/api/watch/" + encodeURIComponent(b.dataset.ack) + "/ack", {method: "POST"}); renderWatch(); } catch (e) { toast(e.message); }
  }));
  $("#wList").querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", async () => {
    if (!confirm("确定删除这个关注项？")) return;
    try { await api("/api/watch/" + encodeURIComponent(b.dataset.del), {method: "DELETE"}); renderWatch(); } catch (e) { toast(e.message); }
  }));
}

/* ================= 批量研判 ================= */
function renderBatch() {
  const saved = sessionStorage.getItem("batchText") || "";
  view.innerHTML = `
  <div class="ihead"><div class="wrap"><div class="ihead-in"><div><h1>批量研判</h1>
    <p>粘贴 IOC 清单，或整段报告 / 告警日志 / 邮件正文：自动还原 hxxp、[.] 等防护写法，提取 IP、域名、URL、哈希后逐条比对主库与情报文章（单次最多 500 条）</p></div></div></div></div>
  <div class="wrap page-body">
    <div class="card">
      <div class="card-h"><h3>输入</h3><span class="muted" id="bHint"></span><div class="r">
        <label class="btn" for="bFile">导入文件</label><input type="file" id="bFile" accept=".txt,.csv,.log,.json,.md,.eml,.ioc" hidden>
        <button class="btn" id="bClear">清空</button>
        <button class="btn primary" id="bRun">提取并研判</button></div></div>
      <div class="card-b"><textarea id="bText" class="btext" spellcheck="false" placeholder="每行一个 IOC，或直接粘贴整段文本，例如：&#10;45.148.10[.]238&#10;hxxps://evil[.]example/payload.exe&#10;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">${esc(saved)}</textarea></div>
    </div>
    <div class="card" id="bResCard" style="display:none;margin-top:16px">
      <div class="card-h"><div class="bsum" id="bSum"></div>
        <div class="seg" id="bSeg"><button data-v="" class="on">全部</button><button data-v="malicious">恶意</button><button data-v="suspicious">可疑</button><button data-v="unknown">未知</button></div>
        <div class="r"><button class="btn" id="bCopyBad">复制恶意 / 可疑</button><button class="btn" id="bCopyAll">复制全部</button><button class="btn" id="bCsv">${ICON.export} 导出 CSV</button></div></div>
      <div id="bTable"></div>
    </div>
  </div>`;
  const ta = $("#bText");
  const hint = () => { $("#bHint").textContent = ta.value.length ? `${num(ta.value.length)} 字符 · Ctrl+Enter 研判` : "Ctrl+Enter 研判"; };
  ta.addEventListener("input", () => { try { sessionStorage.setItem("batchText", ta.value.slice(0, 300000)); } catch (e) {} hint(); });
  hint();
  $("#bClear").onclick = () => { ta.value = ""; sessionStorage.removeItem("batchText"); hint(); ta.focus(); };
  $("#bFile").addEventListener("change", e => {
    const f = e.target.files[0];
    if (!f) return;
    if (f.size > 2 * 1024 * 1024) { toast("文件超过 2MB"); return; }
    const rd = new FileReader();
    rd.onload = () => { ta.value = String(rd.result || "").slice(0, 300000); ta.dispatchEvent(new Event("input")); toast("已导入 " + f.name); };
    rd.readAsText(f);
    e.target.value = "";
  });
  let data = null, filter = "";
  const rows = () => (data ? data.items : []).filter(r => !filter || r.verdict === filter);
  const draw = () => {
    const list = rows();
    $("#bTable").innerHTML = list.length ? `<div class="tbl-wrap"><table class="rtbl btbl"><colgroup><col class="c-v"><col class="c-type"><col><col class="c-fam"><col class="c-src"><col class="c-prof"><col class="c-art"></colgroup>
      <thead><tr><th>判定</th><th>类型</th><th>指标</th><th>恶意家族</th><th>情报来源</th><th>IP 画像</th><th>情报文章</th></tr></thead><tbody>
      ${list.map(r => `<tr class="v-${esc(r.verdict)}"><td>${vtag(r.verdict)}</td>
        <td><span class="tbadge t-${esc(r.kind)}">${esc(TYPE_LABEL[r.kind] || r.kind)}</span></td>
        <td class="val"><a href="${qlink(r.value)}" target="_blank" rel="noopener">${esc(r.value)}</a>${r.parents && !r.records ? `<div class="muted" style="font-size:12px">父域名 / 主机命中 ${num(r.parents)} 条</div>` : ""}</td>
        <td class="cell-fam">${famTags(r.families)}</td>
        <td class="cell-src">${(r.sources || []).map(s => `<span class="tag blue">${esc(s)}</span>`).join("")}</td>
        <td class="cell-prof">${r.profile ? `<span class="tag" title="${esc(r.profile)}">${esc(r.profile)}</span>` : ""}</td>
        <td class="cell-art">${r.article ? `<a data-aid="${r.article.id}" role="button" title="${esc(r.article.title)}">${esc(r.article.title)}</a>${r.articles > 1 ? ` <span class="muted">等 ${num(r.articles)} 篇</span>` : ""}` : ""}</td></tr>`).join("")}
      </tbody></table></div>` : `<div class="empty">没有符合筛选条件的结果</div>`;
    bindArticles($("#bTable"));
  };
  const run = async () => {
    const text = ta.value.trim();
    if (!text) { ta.focus(); return; }
    const btn = $("#bRun");
    btn.disabled = true; btn.textContent = "研判中…";
    try {
      data = await api("/api/batch", {method: "POST", body: {text}});
    } catch (e) { toast(e.message); btn.disabled = false; btn.textContent = "提取并研判"; return; }
    btn.disabled = false; btn.textContent = "提取并研判";
    $("#bResCard").style.display = "";
    if (!data.items.length) { $("#bSum").innerHTML = `<span class="muted">${esc(data.error || "没有识别到 IOC")}</span>`; $("#bTable").innerHTML = ""; return; }
    const s = data.summary || {};
    const sk = data.skipped || {};
    $("#bSum").innerHTML = `共 <b>${num(data.total)}</b> 条${data.truncated ? "（已达上限 500）" : ""}：
      <span class="vtag malicious">恶意 ${num(s.malicious || 0)}</span><span class="vtag suspicious">可疑 ${num(s.suspicious || 0)}</span><span class="vtag unknown">未知 ${num(s.unknown || 0)}</span>
      <span class="muted">${data.list_mode ? "清单模式" : "正文提取"} · ${num(data.elapsed_ms)} ms${sk.private_ip ? ` · 跳过内网 / 保留 IP ${num(sk.private_ip)} 个` : ""}</span>`;
    draw();
    $("#bResCard").scrollIntoView({behavior: "smooth", block: "start"});
  };
  $("#bRun").onclick = run;
  ta.addEventListener("keydown", e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run(); });
  segment($("#bSeg"), v => { filter = v; draw(); });
  $("#bCopyBad").onclick = () => {
    const v = (data ? data.items : []).filter(r => r.verdict === "malicious" || r.verdict === "suspicious").map(r => r.value);
    if (!v.length) { toast("没有恶意 / 可疑结果"); return; }
    copy(v.join("\n"));
  };
  $("#bCopyAll").onclick = () => { const v = rows().map(r => r.value); if (v.length) copy(v.join("\n")); else toast("没有结果"); };
  $("#bCsv").onclick = () => {
    const list = rows();
    if (!list.length) { toast("没有可导出的结果"); return; }
    const csv = "\ufeff" + ["verdict,type,value,families,sources,ip_profile,articles,article_title,db_records,parent_hits",
      ...list.map(r => [VERDICT_TXT[r.verdict] || r.verdict, r.kind, r.value, (r.families || []).join("; "), (r.sources || []).join("; "),
        r.profile, r.articles, r.article ? r.article.title : "", r.records, r.parents].map(csvCell).join(","))].join("\r\n");
    downloadText("batch_" + new Date().toISOString().slice(0, 19).replace(/[:T]/g, "") + ".csv", csv, "text/csv");
  };
}

/* ================= APT / 家族 ================= */
function aptHash(st) {
  const p = new URLSearchParams();
  if (st.tab && st.tab !== "apt") p.set("tab", st.tab);
  if (st.q) p.set("q", st.q);
  if (st.country) p.set("country", st.country);
  if (st.sort && st.sort !== "articles") p.set("sort", st.sort);
  if (st.scope === "all") p.set("scope", "all");
  if (st.page > 1) p.set("page", st.page);
  const s = p.toString();
  return "#/apt" + (s ? "?" + s : "");
}

async function renderApt(params) {
  const st = {
    tab: params.get("tab") === "family" ? "family" : "apt",
    q: (params.get("q") || "").slice(0, 60), country: (params.get("country") || "").slice(0, 40),
    sort: ["articles", "iocs", "recent", "name"].includes(params.get("sort")) ? params.get("sort") : "articles",
    scope: params.get("scope") === "all" ? "all" : "apt",
    page: Math.max(1, parseInt(params.get("page") || "1", 10) || 1),
  };
  const size = st.tab === "apt" ? 24 : 30;
  const go = patch => { location.hash = aptHash({...st, page: 1, ...patch}); };
  const sortLabel = {articles: "文章最多", iocs: "IOC 最多", recent: "最近活跃", name: "名称"};
  view.innerHTML = `
  <div class="ihead"><div class="wrap"><div class="ihead-in">
    <div><h1>APT 组织 / 恶意家族</h1><p>组织档案来自 ETDA Threat Group Cards；IOC 数来自主库家族索引，文章数来自本地情报文章。点进任一组织或家族查看专题</p></div>
    <form class="ifilter" id="aFilter" autocomplete="off">
      <input name="q" maxlength="60" value="${esc(st.q)}" placeholder="${st.tab === "apt" ? "搜索组织名或别名，例如 APT28、Lazarus" : "搜索家族名，例如 AsyncRAT"}" aria-label="搜索">
      <button type="submit">${ICON.search}</button>
    </form></div>
    <div class="topic-bar"><a class="tchip ${st.tab === "apt" ? "on" : ""}" href="${aptHash({tab: "apt"})}">APT 组织</a><a class="tchip ${st.tab === "family" ? "on" : ""}" href="${aptHash({tab: "family"})}">恶意家族</a></div>
  </div></div>
  <div class="wrap page-body"><div class="card">
    <div class="card-h" id="aBar"></div>
    <div id="aList">${skel(8)}</div>
    <div class="pager" id="aPager"></div>
  </div></div>`;
  $("#aFilter").addEventListener("submit", e => { e.preventDefault(); go({q: e.target.q.value.trim().slice(0, 60)}); });
  const seq = routeSeq;
  const qs = new URLSearchParams({offset: (st.page - 1) * size, limit: size});
  if (st.q) qs.set("q", st.q);
  let d;
  try {
    if (st.tab === "apt") {
      qs.set("sort", st.sort); qs.set("scope", st.scope);
      if (st.country) qs.set("country", st.country);
      d = await api("/api/apt_groups?" + qs);
    } else d = await api("/api/families?" + qs);
  } catch (e) { if (seq === routeSeq) $("#aList").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  if (seq !== routeSeq) return;
  const idxNote = d.index && !d.index.ready ? `<div class="notice">家族索引尚未建立，IOC 数显示为 0。运行一次 run_all，或执行 <span class="mono">python -X utf8 family_index.py --full</span></div>` : "";
  if (st.tab === "apt") {
    $("#aBar").innerHTML = `<div class="seg" id="aSort">${Object.entries(sortLabel).map(([k, v]) => `<button data-v="${k}" class="${st.sort === k ? "on" : ""}">${v}</button>`).join("")}</div>
      <select class="sel" id="aCountry"><option value="">全部国家 / 地区</option>${(d.countries || []).map(([c, n]) => `<option value="${esc(c)}" ${c === st.country ? "selected" : ""}>${esc(c)}（${n}）</option>`).join("")}</select>
      <label class="chk"><input type="checkbox" id="aScope" ${st.scope === "all" ? "checked" : ""}> 含金融犯罪团伙</label>
      <div class="r muted">共 ${num(d.total)} 个组织</div>`;
    segment($("#aSort"), v => go({sort: v}));
    $("#aCountry").addEventListener("change", e => go({country: e.target.value}));
    $("#aScope").addEventListener("change", e => go({scope: e.target.checked ? "all" : "apt"}));
    $("#aList").innerHTML = idxNote + (d.items.length ? `<div class="aptgrid">${d.items.map(g => `<a class="aptc" href="${profileLink(g.name)}">
        <div class="aptn">${avatar(g.name)}<b>${esc(g.name)}</b>${g.state ? "" : `<span class="tag">金融犯罪</span>`}</div>
        <div class="aptm muted">${esc((g.country || []).join("、") || "归属未知")}${g.first_seen ? ` · 始于 ${esc(g.first_seen)}` : ""}</div>
        <div class="apta">${g.names.filter(n => n !== g.name).slice(0, 4).map(n => `<span class="tag orange">${esc(n)}</span>`).join("")}${g.alias_count > 5 ? `<span class="tag">+${g.alias_count - 5}</span>` : ""}</div>
        <div class="apts"><span><b>${num(g.articles)}</b> 篇文章</span><span><b>${num(g.iocs)}</b> 条 IOC</span>${g.last_article ? `<span class="muted">最近 ${esc(g.last_article)}</span>` : ""}</div>
      </a>`).join("")}</div>` : `<div class="empty" style="padding:60px 0">没有匹配的组织</div>`);
  } else {
    $("#aBar").innerHTML = `<h3>按主库 IOC 数排序</h3><div class="r muted">共 ${num(d.total)} 个家族 / 组织名${d.index && d.index.built_at ? ` · 索引更新于 ${esc(d.index.built_at.replace("T", " "))}` : ""}</div>`;
    $("#aList").innerHTML = idxNote + (d.items.length ? `<div class="tbl-wrap"><table class="rtbl ftbl"><thead><tr><th>家族 / 组织</th><th>IOC 总数</th><th>IP</th><th>域名</th><th>URL</th><th>哈希</th><th>文章</th><th>主要来源</th></tr></thead><tbody>
      ${d.items.map(f => `<tr><td><a href="${profileLink(f.name)}"><b>${esc(f.name)}</b></a>${f.apt ? ` <span class="tag orange" title="ETDA 组织">${esc(f.apt)}</span>` : ""}</td>
        <td><b>${num(f.total)}</b></td><td>${num(f.counts.ip)}</td><td>${num(f.counts.domain)}</td><td>${num(f.counts.url)}</td><td>${num(f.counts.file_hash)}</td>
        <td>${num(f.articles)}</td><td class="cell-src">${Object.keys(f.sources || {}).slice(0, 3).map(s => `<span class="tag blue">${esc(s)}</span>`).join("")}</td></tr>`).join("")}
      </tbody></table></div>` : `<div class="empty" style="padding:60px 0">没有匹配的家族</div>`);
  }
  const pages = Math.max(1, Math.ceil(d.total / size));
  const pg = $("#aPager");
  pg.innerHTML = pages > 1 ? `<span class="muted">第 ${st.page} / ${pages} 页</span><div class="pgs">${pager(st.page, pages)}</div>` : "";
  pg.querySelectorAll(".pg[data-p]").forEach(b => b.addEventListener("click", () => {
    const p = +b.dataset.p;
    if (p >= 1 && p <= pages) location.hash = aptHash({...st, page: p});
  }));
}

async function renderProfile(name) {
  name = (name || "").trim();
  if (!name) { location.hash = "#/apt"; return; }
  view.innerHTML = `<div class="ihead"><div class="wrap"><div class="ihead-in"><div><h1>${esc(name)}</h1><p>正在加载专题…</p></div></div></div></div>
    <div class="wrap page-body"><div class="card"><div class="card-b">${skel(8)}</div></div></div>`;
  const seq = routeSeq;
  let d;
  try { d = await api("/api/profile?name=" + encodeURIComponent(name)); }
  catch (e) { if (seq === routeSeq) view.querySelector(".page-body").innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
  if (seq !== routeSeq) return;
  const c = d.counts || {};
  const isApt = !!d.actor_profile;
  const maxT = Math.max(1, ...d.trend.map(t => t.count));
  const stats = [["IOC 总数", c.total], ["IP", c.ip], ["域名", c.domain], ["URL", c.url], ["文件哈希", c.file_hash], ["相关文章", d.article_total]];
  const typeTabs = [["", "全部"], ["ip", "IP"], ["domain", "域名"], ["url", "URL"], ["file_hash", "哈希"]];
  view.innerHTML = `
  <div class="ihead"><div class="wrap"><div class="ihead-in">
    <div><h1>${esc(d.name)} <span class="ptype">${isApt ? "APT 组织" : "恶意家族"}</span></h1>
      <p>${d.query.toLowerCase() !== d.name.toLowerCase() ? `查询「${esc(d.query)}」是 ${esc(d.name)} 的别名；` : ""}IOC 统计合并了${isApt ? "该组织全部别名" : "该家族名"}在主库中的记录${d.index && d.index.built_at ? `（索引更新于 ${esc(d.index.built_at.replace("T", " "))}）` : ""}</p></div>
    <div class="pact">${watchBtnHtml(d.watch ? d.watch.id : "")}<a class="btn round" href="${qlink(d.query)}">${ICON.search} 主库检索</a><a class="btn round" href="#/apt${isApt ? "" : "?tab=family"}">返回列表</a></div>
    </div>
    <div class="istats">${stats.map(([k, v]) => `<div><b>${num(v || 0)}</b><span>${k}</span></div>`).join("")}</div>
  </div></div>
  <div class="wrap"><div class="ilayout">
    <div class="dcol">
      <div class="card"><div class="card-h"><h3>近 12 个月情报文章</h3><span class="muted">按文章发布月份统计</span></div>
        <div class="trend">${d.trend.map(t => `<div class="tcol" title="${esc(t.month)}：${t.count} 篇"><i style="height:${Math.round(t.count / maxT * 100)}%"></i><b>${t.count || ""}</b><span>${esc(t.month.slice(5))}</span></div>`).join("")}</div></div>
      <div class="card" id="pTabCard">
        <div class="tabs" id="pTabs"><button data-k="ioc" class="on">样例 IOC<span class="cnt">${num(d.samples.length)}</span></button><button data-k="art" class="${d.articles.length ? "" : "zero"}">相关文章<span class="cnt">${num(d.article_total)}</span></button><button data-k="fam" class="${d.families.length ? "" : "zero"}">名称拆分<span class="cnt">${num(d.families.length)}</span></button></div>
        <div id="pBody"></div>
      </div>
    </div>
    <div class="dcol">
      ${actorCard(d.actor_profile)}
      <div class="card"><div class="side-h">主要情报来源</div><div class="side-b">${d.sources.length ? d.sources.map(([s, n]) => `<div class="kvrow"><span class="tag blue">${esc(s)}</span><span class="muted">${num(n)}</span></div>`).join("") : `<span class="muted">暂无</span>`}</div></div>
      <div class="card"><div class="side-h">文章中常同时出现</div><div class="side-b"><div class="cloud">${d.related.length ? d.related.map(([n, k]) => `<a class="tag orange" href="${profileLink(n)}">${esc(n)}<i>${k}</i></a>`).join("") : `<span class="muted">暂无</span>`}</div></div></div>
    </div>
  </div></div>`;
  bindWatchBtn(view.querySelector(".watch-btn"), d.query);
  let tab = "ioc", tf = "", pages = {};
  const body = $("#pBody");
  const show = (k, page) => {
    tab = k;
    if (page != null) pages[k] = page;
    const p = pages[k] || 1;
    $("#pTabs").querySelectorAll("button").forEach(b => b.classList.toggle("on", b.dataset.k === k));
    if (k === "ioc") {
      const rows = d.samples.filter(r => !tf || r.type === tf);
      body.innerHTML = `<div class="card-h"><div class="seg" id="pType">${typeTabs.map(([v, l]) => `<button data-v="${v}" class="${tf === v ? "on" : ""}">${l}</button>`).join("")}</div>
        <span class="muted">每种类型展示主库最新 60 条，完整数量见上方统计</span></div>${recTable(rows, false, p)}`;
      segment($("#pType"), v => { tf = v; pages.ioc = 1; show("ioc"); });
    } else if (k === "art") body.innerHTML = artTable(d.articles, p) + (d.article_total > d.articles.length ? `<div class="notice">共 ${num(d.article_total)} 篇，显示最新 ${d.articles.length} 篇</div>` : "");
    else body.innerHTML = d.families.length ? `<div class="tbl-wrap"><table class="rtbl ftbl"><thead><tr><th>库内名称</th><th>IOC</th><th>IP</th><th>域名</th><th>URL</th><th>哈希</th></tr></thead><tbody>
      ${d.families.map(f => `<tr><td><a href="${qlink(f.name)}">${esc(f.name)}</a></td><td><b>${num(f.total)}</b></td><td>${num(f.counts.ip)}</td><td>${num(f.counts.domain)}</td><td>${num(f.counts.url)}</td><td>${num(f.counts.file_hash)}</td></tr>`).join("")}
      </tbody></table></div>` : `<div class="empty">主库里没有以该名称标记的 IOC</div>`;
    bindArticles(body);
    body.querySelectorAll(".pg[data-p]").forEach(b => b.addEventListener("click", () => show(tab, +b.dataset.p)));
  };
  $("#pTabs").querySelectorAll("button").forEach(b => b.addEventListener("click", () => show(b.dataset.k)));
  show("ioc");
}

/* ================= 路由 ================= */
function route() {
  routeSeq++;
  closeModal();
  const h = location.hash || "#/";
  const [path, qs] = h.slice(1).split("?");
  const params = new URLSearchParams(qs || "");
  const PAGES = {"/search": "search", "/intel": "intel", "/darkweb": "darkweb", "/apt": "apt", "/profile": "apt",
    "/batch": "batch", "/watch": "watch"};
  const name = PAGES[path] || "home";
  const topicNav = name === "intel" && TOPIC_LABEL[params.get("topic")] ? "topic-" + params.get("topic") : "";
  document.querySelectorAll(".nav-links > a").forEach(a => {
    const key = a.dataset.r;
    // 进入专项主题时，顶栏只点亮「专项情报」下拉，不点亮「情报动态」
    a.classList.toggle("active", !topicNav && key === name);
  });
  const drop = $("#navTopics");
  if (drop) {
    drop.classList.toggle("active", !!topicNav);
    drop.classList.remove("open");
    drop.querySelector(".nav-drop-btn")?.setAttribute("aria-expanded", "false");
    drop.querySelectorAll(".nav-drop-menu a").forEach(a => {
      a.classList.toggle("active", !!topicNav && a.dataset.r === topicNav);
    });
  }
  const ns = $("#navSearch");
  ns.classList.toggle("show", name !== "home");
  ns.innerHTML = name !== "home" ? searchBox("sm", name === "search" ? params.get("q") || "" : "") : "";
  window.scrollTo(0, 0);
  if (name === "search") renderSearch(params.get("q") || "");
  else if (name === "intel") renderIntel(params);
  else if (name === "darkweb") renderDarkweb(params);
  else if (path === "/profile") renderProfile(params.get("name") || "");
  else if (name === "apt") renderApt(params);
  else if (name === "batch") renderBatch();
  else if (name === "watch") renderWatch();
  else renderHome();
}
window.addEventListener("hashchange", route);

/* 专项情报下拉 */
(function bindNavTopics() {
  const drop = $("#navTopics");
  if (!drop) return;
  const btn = drop.querySelector(".nav-drop-btn");
  btn?.addEventListener("click", e => {
    e.stopPropagation();
    const open = !drop.classList.contains("open");
    drop.classList.toggle("open", open);
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  });
  drop.querySelectorAll(".nav-drop-menu a").forEach(a => a.addEventListener("click", e => {
    drop.classList.remove("open");
    btn?.setAttribute("aria-expanded", "false");
    if (a.id === "navSubmit" || a.dataset.r === "submit") {
      e.preventDefault();
      openSubmitModal();
    }
  }));
  document.addEventListener("click", e => {
    if (!drop.contains(e.target)) {
      drop.classList.remove("open");
      btn?.setAttribute("aria-expanded", "false");
    }
  });
})();
document.addEventListener("keydown", e => {
  if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
  const tag = (document.activeElement?.tagName || "").toLowerCase();
  if (tag === "input" || tag === "textarea") return;
  const input = $(".hero .sbox input") || $("#navSearch input");
  if (input) { e.preventDefault(); input.focus(); input.select(); }
});
const totop = $("#totop");
window.addEventListener("scroll", () => totop.classList.toggle("show", window.scrollY > 500), {passive: true});
totop.addEventListener("click", () => window.scrollTo({top: 0, behavior: "smooth"}));
startStatusPoll();
refreshWatchBadge();
setInterval(refreshWatchBadge, 300000);
route();
