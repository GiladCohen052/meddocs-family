/* The family mobile view: Hebrew RTL, iPhone Safari first. Shared by the iCloud `index.html`
 * (where it is inlined into a <script> - so this file must never contain a closing script tag
 * literal) and by the encrypted GitHub Pages site (where it is loaded as a plain script).
 *
 * window.MedView = { SHELL_HTML, boot(bundle, loadPage, opts) }
 *   bundle   {documents, regions, labs, thumbs, lab_tests, open_followups, title, generated_at}
 *   loadPage (file) -> src string, or a promise of one - `file` is the snapshot's "pages/<doc>_<n>.jpg"
 *   opts     {container: element (default #app), lock: function (adds a "נעילה" button)}
 * Everything rendered from data goes through textContent/createElement; SHELL_HTML is static markup.
 */
(function () {
"use strict";

var SHELL_HTML =
  '<header id="topbar">' +
    '<h1><span id="title"></span></h1>' +
    '<div id="updated"></div>' +
    '<div id="filters">' +
      '<input type="search" id="q" placeholder="חיפוש: תקציר, מוסד, רופא, איבר, תגית">' +
      '<div id="chips"></div>' +
    '</div>' +
  '</header>' +
  '<main>' +
    '<section id="tab-timeline"><div id="list"></div></section>' +
    '<section id="tab-labs" hidden><div id="labs"></div></section>' +
    '<section id="tab-followups" hidden><div id="followups"></div></section>' +
  '</main>' +
  '<nav id="tabbar">' +
    '<button type="button" id="btn-timeline">ציר זמן</button>' +
    '<button type="button" id="btn-labs">ערכי דם</button>' +
    '<button type="button" id="btn-followups">מעקבים</button>' +
  '</nav>' +
  '<section id="doc-view" hidden>' +
    '<header id="doc-bar"><button type="button" id="back">חזרה ›</button><div id="doc-head"></div></header>' +
    '<div id="doc-body"></div>' +
  '</section>';

var MONTHS = ["ינואר", "פברואר", "מרץ", "אפריל", "מאי", "יוני", "יולי", "אוגוסט", "ספטמבר",
              "אוקטובר", "נובמבר", "דצמבר"];
var TABS = ["timeline", "labs", "followups"];
var DEFAULT_TITLE = "בדיקות של סבתא";

function boot(bundle, loadPage, opts) {
opts = opts || {};
var container = opts.container || document.getElementById("app");
container.innerHTML = SHELL_HTML;

var DATA = bundle || {};
var THUMBS = DATA.thumbs || {};
var LAB_TESTS = DATA.lab_tests || [];
var OPEN_FOLLOWUPS = DATA.open_followups || [];
var state = { q: "", region: "", tab: "timeline" };

function id(name) { return document.getElementById(name); }
function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) { e.className = cls; }
  if (text !== undefined && text !== null && text !== "") { e.textContent = String(text); }
  return e;
}
function num(v) { return v === null || v === undefined ? "" : String(v); }
function fmtDate(iso) {
  if (!iso) { return "ללא תאריך"; }
  var p = String(iso).split("-");
  return p.length === 3 ? p[2] + "/" + p[1] + "/" + p[0] : String(iso);
}
function fmtStamp(iso) {
  var d = new Date(iso);
  if (!iso || isNaN(d.getTime())) { return String(iso || ""); }
  function p(n) { return (n < 10 ? "0" : "") + n; }
  return p(d.getDate()) + "/" + p(d.getMonth() + 1) + "/" + d.getFullYear() + " " +
    p(d.getHours()) + ":" + p(d.getMinutes());
}
function monthLabel(iso) {
  if (!iso) { return "ללא תאריך"; }
  var p = String(iso).split("-");
  return MONTHS[parseInt(p[1], 10) - 1] + " " + p[0];
}
function refRange(low, high) {
  if ((low === null || low === undefined) && (high === null || high === undefined)) { return ""; }
  return num(low) + "–" + num(high);
}
function flagLabel(flag) { return flag === "H" ? "גבוה" : flag === "L" ? "נמוך" : ""; }
function cell(cls, flag) { return flag ? cls + " " + flag : cls; }  // "num H" colours an out-of-range value
function line(cls, parts) {
  // A line of Hebrew text with isolated left-to-right islands: ["טקסט", ["ltr", "12/01/2026"], ...].
  var e = el("div", cls);
  parts.forEach(function (part) {
    if (!part) { return; }
    if (typeof part === "string") { e.appendChild(el("span", null, part)); }
    else { e.appendChild(el("span", "ltr", part[1])); }
  });
  return e;
}
function isoDay(offset) {
  var d = new Date();
  d.setDate(d.getDate() + (offset || 0));
  function p(n) { return (n < 10 ? "0" : "") + n; }
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate());
}
function setPageSrc(img, page) {
  // `loadPage` may answer at once (the iCloud page has the images inlined) or with a promise
  // (the encrypted site fetches and decrypts them); either way the <img> is already in place,
  // so the page order never depends on which download finishes first.
  var fail = function () { img.alt = "התמונה לא זמינה"; };
  var result;
  try { result = loadPage(page.file); } catch (e) { fail(); return; }
  if (result && typeof result.then === "function") {
    result.then(function (src) { if (src) { img.src = src; } else { fail(); } }, fail);
  } else if (result) {
    img.src = result;
  } else {
    fail();
  }
}

/* ---------- timeline ---------- */
function haystack(d) {
  var parts = [d.summary, d.institution, d.doctor, d.category_label, d.followup_text];
  parts = parts.concat(d.organ_labels || [], d.region_labels || [], d.tags || []);
  return parts.filter(Boolean).join(" ").toLowerCase();
}
function visibleDocs() {
  var q = state.q.trim().toLowerCase();
  return (DATA.documents || []).filter(function (d) {
    if (state.region && (d.regions || []).indexOf(state.region) < 0) { return false; }
    return !q || haystack(d).indexOf(q) >= 0;
  });
}
function renderChips() {
  var box = id("chips");
  box.textContent = "";
  function chip(label, region) {
    var c = el("button", "chip", label);
    c.type = "button";
    c.setAttribute("aria-pressed", state.region === region ? "true" : "false");
    c.addEventListener("click", function () {
      state.region = state.region === region ? "" : region;
      renderChips();
      renderTimeline();
    });
    box.appendChild(c);
  }
  chip("הכל", "");
  (DATA.regions || []).forEach(function (r) {
    if (r.count) { chip(r.label + " (" + r.count + ")", r.region); }
  });
}
function docCard(d) {
  var b = el("button", "card");
  b.type = "button";
  var img = el("img");
  if (THUMBS[String(d.id)]) { img.src = THUMBS[String(d.id)]; }
  img.alt = "";
  b.appendChild(img);
  var body = el("div", "body");
  body.appendChild(el("div", "date", fmtDate(d.exam_date)));
  body.appendChild(el("div", "type", d.category_label +
    ((d.organ_labels || []).length ? " · " + d.organ_labels.join(", ") : "")));
  if (d.institution) { body.appendChild(el("div", "sub", d.institution)); }
  if (d.summary) { body.appendChild(el("div", "sum", d.summary)); }
  if ((d.tags || []).length) {
    var tags = el("div");
    d.tags.forEach(function (t) { tags.appendChild(el("span", "tag", t)); });
    body.appendChild(tags);
  }
  b.appendChild(body);
  b.addEventListener("click", function () { showDoc(d); });
  return b;
}
function renderTimeline() {
  var list = id("list");
  list.textContent = "";
  var docs = visibleDocs();
  if (!docs.length) {
    list.appendChild(el("div", "empty", "לא נמצאו מסמכים"));
    return;
  }
  var current = null;
  docs.forEach(function (d) {
    var label = monthLabel(d.exam_date);
    if (label !== current) {
      current = label;
      list.appendChild(el("div", "month", label));
    }
    list.appendChild(docCard(d));
  });
}

/* ---------- document view ---------- */
function fieldRow(table, label, value) {
  if (!value) { return; }
  var tr = el("tr");
  tr.appendChild(el("th", null, label));
  tr.appendChild(el("td", null, value));
  table.appendChild(tr);
}
function labTable(labs) {
  var t = el("table", "labs");
  var head = el("tr");
  ["בדיקה", "תוצאה", "טווח תקין", "סימון"].forEach(function (h) { head.appendChild(el("th", null, h)); });
  t.appendChild(head);
  labs.forEach(function (l) {
    var tr = el("tr");
    tr.appendChild(el("td", null, l.test_name_raw || l.test_key));
    var value = l.value !== null && l.value !== undefined ? num(l.value) : (l.value_text || "");
    tr.appendChild(el("td", cell("num", l.flag), value + (l.unit ? " " + l.unit : "")));
    tr.appendChild(el("td", "num", refRange(l.ref_low, l.ref_high)));
    tr.appendChild(el("td", cell("flag", l.flag), flagLabel(l.flag)));
    t.appendChild(tr);
  });
  return t;
}
function showDoc(d) {
  var body = id("doc-body");
  body.textContent = "";
  id("doc-head").textContent = fmtDate(d.exam_date) + " · " + d.category_label;
  var fields = el("table", "fields");
  fieldRow(fields, "תאריך", fmtDate(d.exam_date));
  fieldRow(fields, "סוג", d.category_label);
  fieldRow(fields, "איברים", (d.organ_labels || []).join(", "));
  fieldRow(fields, "מוסד", d.institution);
  fieldRow(fields, "רופא", d.doctor);
  fieldRow(fields, "תקציר", d.summary);
  fieldRow(fields, "תגיות", (d.tags || []).join(", "));
  var panel = el("div", "panel");
  panel.appendChild(fields);
  body.appendChild(panel);
  if (d.followup_text || d.followup_due) {
    var fu = el("div", "followup");
    fu.appendChild(el("div", "k", "המלצת מעקב"));
    if (d.followup_text) { fu.appendChild(el("div", null, d.followup_text)); }
    if (d.followup_due) { fu.appendChild(line("due", ["עד ", ["ltr", fmtDate(d.followup_due)]])); }
    body.appendChild(fu);
  }
  if ((d.lab_results || []).length) {
    var labs = el("div", "panel");
    labs.appendChild(el("h3", "section", "בדיקות דם במסמך"));
    labs.appendChild(labTable(d.lab_results));
    body.appendChild(labs);
  }
  var pages = el("div", "pages");
  (d.pages || []).forEach(function (p) {
    var img = el("img", "page");
    img.alt = "עמוד " + p.page_no;
    pages.appendChild(img);
    setPageSrc(img, p);
  });
  body.appendChild(pages);
  var view = id("doc-view");
  view.hidden = false;
  view.scrollTop = 0;
}
function closeDoc() { id("doc-view").hidden = true; }

/* ---------- labs tab ---------- */
function chartSvg(series) {
  // The namespace is built from parts on purpose: the page must not contain a URL of any kind.
  var NS = "http" + "://www.w3.org/2000/svg";
  function node(tag, attrs, text) {
    var e = document.createElementNS(NS, tag);
    Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (text !== undefined) { e.textContent = text; }
    return e;
  }
  var W = 320, H = 140, L = 34, R = 8, T = 10, B = 24;
  var svg = node("svg", { viewBox: "0 0 " + W + " " + H, "class": "chart", "aria-hidden": "true",
                          style: "direction:ltr" });
  var xs = series.map(function (p) { return new Date(p.date).getTime(); });
  var low = null, high = null;
  series.forEach(function (p) {
    if (low === null && p.ref_low !== null && p.ref_low !== undefined) { low = p.ref_low; }
    if (high === null && p.ref_high !== null && p.ref_high !== undefined) { high = p.ref_high; }
  });
  var all = series.map(function (p) { return p.value; })
    .concat(low === null ? [] : [low], high === null ? [] : [high]);
  var minY = Math.min.apply(null, all), maxY = Math.max.apply(null, all);
  if (minY === maxY) { minY -= 1; maxY += 1; }
  var pad = (maxY - minY) * 0.15;
  minY -= pad;
  maxY += pad;
  var minX = Math.min.apply(null, xs), maxX = Math.max.apply(null, xs);
  if (maxX === minX) { maxX = minX + 86400000; }
  function x(t) { return (L + (t - minX) / (maxX - minX) * (W - L - R)).toFixed(1); }
  function y(v) { return (T + (maxY - v) / (maxY - minY) * (H - T - B)).toFixed(1); }
  if (low !== null || high !== null) {
    var top = high === null ? T : Number(y(high)), bottom = low === null ? H - B : Number(y(low));
    svg.appendChild(node("rect", { x: L, y: top, width: W - L - R,
                                   height: Math.max(0, bottom - top), fill: "#def7ec" }));
  }
  [maxY, minY].forEach(function (v) {
    svg.appendChild(node("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), stroke: "#e5e7eb" }));
    svg.appendChild(node("text", { x: L - 4, y: Number(y(v)) + 3, "text-anchor": "end",
                                   "font-size": 9, fill: "#667085" }, v.toFixed(1)));
  });
  svg.appendChild(node("path", {
    d: series.map(function (p, i) { return (i ? "L" : "M") + x(xs[i]) + "," + y(p.value); }).join(" "),
    fill: "none", stroke: "#2b6cb0", "stroke-width": 2 }));
  series.forEach(function (p, i) {
    svg.appendChild(node("circle", { cx: x(xs[i]), cy: y(p.value), r: 3.5,
                                     fill: p.flag ? "#c53030" : "#2b6cb0" }));
  });
  [0, series.length - 1].forEach(function (i, k) {
    if (k && series.length < 2) { return; }
    svg.appendChild(node("text", { x: x(xs[i]), y: H - 6, "text-anchor": k ? "end" : "start",
                                   "font-size": 9, fill: "#667085" }, fmtDate(series[i].date)));
  });
  return svg;
}
function labCard(test, series) {
  var card = el("div", "lab");
  card.appendChild(el("h3", null, test.label));
  var last = series[series.length - 1];
  var range = refRange(last.ref_low, last.ref_high);
  card.appendChild(line("sub", ["אחרון: ", ["ltr", fmtDate(last.date)], " · ",
    ["ltr", num(last.value) + (last.unit ? " " + last.unit : "")],
    range ? " · תקין " : "", range ? ["ltr", range] : ""]));
  card.appendChild(chartSvg(series));
  var t = el("table", "labs");
  var head = el("tr");
  ["תאריך", "תוצאה", "טווח תקין", "סימון"].forEach(function (h) { head.appendChild(el("th", null, h)); });
  t.appendChild(head);
  series.slice().reverse().forEach(function (p) {
    var tr = el("tr");
    tr.appendChild(el("td", "num", fmtDate(p.date)));
    tr.appendChild(el("td", cell("num", p.flag), num(p.value) + (p.unit ? " " + p.unit : "")));
    tr.appendChild(el("td", "num", refRange(p.ref_low, p.ref_high)));
    tr.appendChild(el("td", cell("flag", p.flag), flagLabel(p.flag)));
    t.appendChild(tr);
  });
  card.appendChild(t);
  return card;
}
function renderLabs() {
  var box = id("labs");
  box.textContent = "";
  var any = false;
  LAB_TESTS.forEach(function (test) {
    var series = (DATA.labs || {})[test.test_key] || [];
    if (!series.length) { return; }
    any = true;
    box.appendChild(labCard(test, series));
  });
  if (!any) { box.appendChild(el("div", "empty", "אין ערכי דם")); }
}

/* ---------- follow-ups tab ---------- */
function followupRow(d, kind) {
  var b = el("button", "fu " + kind);
  b.type = "button";
  b.appendChild(el("div", "due", fmtDate(d.followup_due)));
  var body = el("div", "body");
  body.appendChild(el("div", "type", d.followup_text || "מעקב"));
  body.appendChild(line("sub", [d.category_label + " מ-", ["ltr", fmtDate(d.exam_date)],
    d.institution ? " · " + d.institution : ""]));
  b.appendChild(body);
  b.addEventListener("click", function () { showDoc(d); });
  return b;
}
function renderFollowups() {
  var box = id("followups");
  box.textContent = "";
  var open = {};
  OPEN_FOLLOWUPS.forEach(function (docId) { open[String(docId)] = true; });
  var docs = (DATA.documents || []).filter(function (d) {
    return open[String(d.id)] && d.followup_due;
  }).sort(function (a, b) { return a.followup_due < b.followup_due ? -1 : 1; });
  if (!docs.length) {
    box.appendChild(el("div", "empty", "אין מעקבים פתוחים"));
    return;
  }
  var today = isoDay(0), soon = isoDay(30);
  var groups = [["overdue", "באיחור", []], ["soon", "בקרוב", []], ["later", "בהמשך", []]];
  docs.forEach(function (d) {
    groups[d.followup_due < today ? 0 : (d.followup_due <= soon ? 1 : 2)][2].push(d);
  });
  groups.forEach(function (g) {
    if (!g[2].length) { return; }
    box.appendChild(el("div", "fu-group", g[1]));
    g[2].forEach(function (d) { box.appendChild(followupRow(d, g[0])); });
  });
}

/* ---------- tabs + boot ---------- */
function setTab(name) {
  state.tab = name;
  TABS.forEach(function (t) {
    id("tab-" + t).hidden = t !== name;
    id("btn-" + t).setAttribute("aria-current", t === name ? "true" : "false");
  });
  id("filters").hidden = name !== "timeline";
  window.scrollTo(0, 0);
}
id("title").textContent = DATA.title || DEFAULT_TITLE;
id("q").addEventListener("input", function (e) {
  state.q = (e.target && e.target.value) || "";
  renderTimeline();
});
id("back").addEventListener("click", closeDoc);
TABS.forEach(function (t) { id("btn-" + t).addEventListener("click", function () { setTab(t); }); });
var updated = id("updated");
updated.textContent = (DATA.documents || []).length + " מסמכים · עודכן " + fmtStamp(DATA.generated_at);
if (typeof opts.lock === "function") {
  var lockBtn = el("button", "chip", "נעילה");
  lockBtn.type = "button";
  lockBtn.id = "lockbtn";
  lockBtn.addEventListener("click", function () { opts.lock(); });
  if (updated.parentNode) { updated.parentNode.insertBefore(lockBtn, updated.nextSibling); }
}
renderChips();
renderTimeline();
renderLabs();
renderFollowups();
setTab("timeline");
}

window.MedView = { SHELL_HTML: SHELL_HTML, boot: boot };
})();
