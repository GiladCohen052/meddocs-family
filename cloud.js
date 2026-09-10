/* The encrypted family site with per-device approval: the phone owns an ECDH P-256 key pair
 * (private half non-extractable, kept in IndexedDB), shows a public "request code" until the PC
 * lists this device in data/manifest.json, then unwraps the data key (ECDH -> HKDF -> AES-GCM),
 * verifies it, caches it, decrypts the snapshot and hands it to MedView. Page images are
 * decrypted on demand into object URLs. Plain ES5 + Promises: iOS 15 Safari is the target.
 *
 * Blob layout (must match app/server/cloud.py): nonce(12) || AES-256-GCM ciphertext || tag(16),
 * with the blob's manifest path (e.g. "data/snapshot.bin") as the additional authenticated data.
 *
 * The crypto contract (docs/superpowers/plans/2026-09-11-meddocs-plan8-device-approval.md):
 *   request code = base64url, no padding, of the compressed public key (33 bytes) -> 44 chars
 *   device id    = first 16 hex of SHA-256(compressed public key)
 *   wrap keys    = HKDF-SHA256(ECDH shared x, salt "meddocs-wrap-v1", info device id, 64 bytes)
 *   wrapped      = encrypt(wrap_aes, path "device/<id>", aes half of the data key) -> 60 bytes
 *
 * window.MedCloud = { generateDeviceKey, compressPublic, requestCode, deviceId, unwrapDataKey,
 *                     decryptBlob, splitBlob } - the pure helpers, also run under node.
 */
(function () {
"use strict";

var MANIFEST_URL = "data/manifest.json";
var MANIFEST_VERSION = 2;
var VERIFY_TEXT = "meddocs-family-v1";
var WRAP_SALT = "meddocs-wrap-v1";
var DB_NAME = "meddocs-family";
var STORE = "keys";
var RECORD_ID = "main";
var POLL_MS = 20000;
var SITE_TITLE = "בדיקות של סבתא";

var subtle = typeof crypto !== "undefined" && crypto.subtle ? crypto.subtle : null;

function utf8(s) { return new TextEncoder().encode(String(s)); }
// Standard base64 (the manifest); base64url and missing padding are tolerated too.
function b64decode(s) {
  var clean = String(s).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  while (clean.length % 4) { clean += "="; }
  var bin = atob(clean);
  var out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
  return out;
}
// bytes -> base64url without padding (RFC 4648 section 5): the request code alphabet.
function b64url(bytes) {
  var u = toBytes(bytes);
  var bin = "";
  for (var i = 0; i < u.length; i++) { bin += String.fromCharCode(u[i]); }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function hex(bytes) {
  var u = toBytes(bytes);
  var out = "";
  for (var i = 0; i < u.length; i++) { out += (u[i] < 16 ? "0" : "") + u[i].toString(16); }
  return out;
}
function toBytes(blob) {
  if (blob instanceof Uint8Array) { return blob; }
  if (blob instanceof ArrayBuffer) { return new Uint8Array(blob); }
  if (blob && blob.buffer instanceof ArrayBuffer) {
    return new Uint8Array(blob.buffer, blob.byteOffset || 0, blob.byteLength);
  }
  throw new Error("blob must be bytes");
}

/* ---------- pure helpers ---------- */

function noCrypto() { return Promise.reject(new Error("WebCrypto is not available")); }

// -> Promise<{privateKey: CryptoKey (ECDH P-256, non-extractable, deriveBits), publicRaw: Uint8Array(65)}>
function generateDeviceKey() {
  if (!subtle) { return noCrypto(); }
  var pair = null;
  return subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])
    .then(function (p) { pair = p; return subtle.exportKey("raw", p.publicKey); })
    .then(function (raw) { return { privateKey: pair.privateKey, publicRaw: new Uint8Array(raw) }; });
}

// Uncompressed point 0x04||x||y (65 bytes) -> compressed 0x02/0x03||x (33 bytes).
function compressPublic(publicRaw) {
  var u = toBytes(publicRaw);
  if (u.length !== 65 || u[0] !== 4) { throw new Error("not an uncompressed P-256 point"); }
  var out = new Uint8Array(33);
  out[0] = (u[64] & 1) ? 3 : 2;
  out.set(u.subarray(1, 33), 1);
  return out;
}

function requestCode(publicRaw) { return b64url(compressPublic(publicRaw)); }

// -> Promise<string>: first 16 hex characters of SHA-256(compressed public key).
function deviceId(publicRaw) {
  if (!subtle) { return noCrypto(); }
  var compressed;
  try { compressed = compressPublic(publicRaw); } catch (e) { return Promise.reject(e); }
  return subtle.digest("SHA-256", compressed).then(function (d) { return hex(d).slice(0, 16); });
}

// Device private key + the manifest's pc_key / this device's wrapped entry -> the data key as a
// non-extractable AES-GCM CryptoKey (decrypt only). Rejects when the wrap does not open.
function unwrapDataKey(privateKey, pcKeyB64, devId, wrappedB64) {
  if (!subtle) { return noCrypto(); }
  var pcPublic, wrapped;
  try { pcPublic = b64decode(pcKeyB64); wrapped = b64decode(wrappedB64); } catch (e) { return Promise.reject(e); }
  return subtle.importKey("raw", pcPublic, { name: "ECDH", namedCurve: "P-256" }, false, [])
    .then(function (pub) {
      return subtle.deriveBits({ name: "ECDH", public: pub }, privateKey, 256);
    })
    .then(function (shared) {
      return subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    })
    .then(function (hkdf) {
      return subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(WRAP_SALT), info: utf8(devId) },
                               hkdf, 512);
    })
    .then(function (out) {
      var wrapAes = new Uint8Array(out).slice(0, 32);   // out[32:] is the PC's nonce key: unused here
      return subtle.importKey("raw", wrapAes, { name: "AES-GCM" }, false, ["decrypt"]);
    })
    .then(function (wrapKey) { return decryptBlob(wrapKey, "device/" + devId, wrapped); })
    .then(function (aes) {
      if (aes.length !== 32) { throw new Error("unwrapped key has the wrong size"); }
      return subtle.importKey("raw", aes, { name: "AES-GCM" }, false, ["decrypt"]);
    });
}

function splitBlob(blob) {
  var u = toBytes(blob);
  if (u.length < 12 + 16) { throw new Error("blob too short"); }
  return { nonce: u.slice(0, 12), body: u.slice(12) };
}

// -> Promise<Uint8Array> of the plaintext; rejects on a wrong key, wrong path or corrupt blob.
function decryptBlob(key, path, blob) {
  if (!subtle) { return noCrypto(); }
  var parts;
  try { parts = splitBlob(blob); } catch (e) { return Promise.reject(e); }
  return subtle.decrypt({ name: "AES-GCM", iv: parts.nonce, additionalData: utf8(path), tagLength: 128 },
                        key, parts.body)
    .then(function (pt) { return new Uint8Array(pt); });
}

if (typeof window !== "undefined") {
  window.MedCloud = { generateDeviceKey: generateDeviceKey, compressPublic: compressPublic,
                      requestCode: requestCode, deviceId: deviceId, unwrapDataKey: unwrapDataKey,
                      decryptBlob: decryptBlob, splitBlob: splitBlob };
}

if (typeof document === "undefined") { return; }  // node: only the helpers above

/* ---------- device record (IndexedDB) ----------
 * {id: "main", privateKey: CryptoKey, publicRaw: Uint8Array, devId: string,
 *  dataKey: CryptoKey | null, keyId: string | null, approvedOnce: boolean}
 * Non-extractable CryptoKeys survive the structured clone into IndexedDB on Safari and Chrome.
 */

function openDb() {
  return new Promise(function (resolve, reject) {
    if (typeof indexedDB === "undefined") { reject(new Error("no IndexedDB")); return; }
    var req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = function () { req.result.createObjectStore(STORE, { keyPath: "id" }); };
    req.onsuccess = function () { resolve(req.result); };
    req.onerror = function () { reject(req.error || new Error("IndexedDB open failed")); };
    req.onblocked = function () { reject(new Error("IndexedDB blocked")); };
  });
}
function withStore(mode, fn) {
  return openDb().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(STORE, mode);
      var req = fn(tx.objectStore(STORE));
      tx.oncomplete = function () { db.close(); resolve(req ? req.result : undefined); };
      tx.onerror = function () { db.close(); reject(tx.error || new Error("IndexedDB failed")); };
      tx.onabort = tx.onerror;
    });
  });
}
function recordGet() { return withStore("readonly", function (s) { return s.get(RECORD_ID); }); }
function recordPut(rec) { rec.id = RECORD_ID; return withStore("readwrite", function (s) { return s.put(rec); }); }
function recordDelete() { return withStore("readwrite", function (s) { return s.delete(RECORD_ID); }); }

/* ---------- boot flow ---------- */

var manifest = null;
var record = null;          // the IndexedDB record above (kept in memory when storage is unavailable)
var key = null;             // the data key once unwrapped and verified
var pollTimer = null;
var statusTimer = null;
var pageUrls = new Map();   // snapshot file -> Promise<object URL>
var objectUrls = [];        // everything to revoke on disconnect

var OFFLINE_MSG = "אין חיבור לאינטרנט וההעתק המקומי חסר";
var NO_NET_MSG = "אין חיבור לאינטרנט";
var BAD_VERSION_MSG = "גרסת האתר לא נתמכת";
var KEY_MISMATCH_MSG = "המפתח לא מתאים, בקשו גישה מחדש";
var WAITING_MSG = "ממתין לאישור…";

function id(name) { return document.getElementById(name); }
function setErr(msg) { id("gate-err").textContent = msg || ""; }
function setBusy(on) { id("gate-busy").hidden = !on; }
function setStatus(msg) { id("gate-status").textContent = msg; }

function isStandalone() {
  if (window.navigator.standalone === true) { return true; }
  try { return window.matchMedia("(display-mode: standalone)").matches; } catch (e) { return false; }
}

// mode: "pending" (never approved: show the request code) or "revoked" (approved before, gone now).
function showGate(mode, msg) {
  id("app").hidden = true;
  id("gate").hidden = false;
  setBusy(false);
  id("gate-pending").hidden = mode !== "pending";
  id("gate-revoked").hidden = mode !== "revoked";
  if (mode === "pending") {
    id("req-code").textContent = record ? requestCode(record.publicRaw) : "";
    id("gate-standalone").hidden = isStandalone();
    setStatus(WAITING_MSG);
  }
  setErr(msg || "");
}

function fetchBytes(url, noStore) {
  return fetch(url, noStore ? { cache: "no-store" } : undefined).then(function (r) {
    if (!r.ok) { throw new Error("HTTP " + r.status + " for " + url); }
    return r.arrayBuffer();
  }).then(toBytes);
}
function parseManifest(m) {
  if (!m || typeof m !== "object") { throw new Error("bad manifest"); }
  if (m.version !== MANIFEST_VERSION) { var e = new Error("unsupported manifest version"); e.badVersion = true; throw e; }
  if (!m.pc_key || !m.key_id || !m.snapshot || !m.verify) { throw new Error("bad manifest"); }
  m.devices = m.devices || {};
  m.pages = m.pages || {};
  return m;
}
// Network first (the service worker answers from its cache when offline); when the worker is not
// in control yet, the Cache API is tried directly before giving up.
function fetchManifest() {
  return fetch(MANIFEST_URL, { cache: "no-store" }).then(function (r) {
    if (!r.ok) { throw new Error("HTTP " + r.status + " for manifest"); }
    return r.json();
  }).then(null, function (err) {
    if (typeof caches === "undefined") { throw err; }
    return caches.match(MANIFEST_URL).then(function (hit) {
      if (!hit) { throw err; }
      return hit.json();
    });
  }).then(parseManifest);
}

function decryptText(k, path, blob) {
  return decryptBlob(k, path, blob).then(function (bytes) { return new TextDecoder().decode(bytes); });
}

// Resolves true when `k` opens verify.bin, false when it does not; rejects on a network failure.
function verifyKey(k) {
  return fetchBytes(manifest.verify, true).then(function (blob) {
    return decryptText(k, manifest.verify, blob)
      .then(function (text) { return text === VERIFY_TEXT; }, function () { return false; });
  });
}

function loadPage(file) {
  var path = manifest.pages[file];
  if (!path) { return Promise.reject(new Error("page not in manifest: " + file)); }
  if (pageUrls.has(file)) { return pageUrls.get(file); }
  var p = fetchBytes(path, false).then(function (blob) {
    return decryptBlob(key, path, blob);
  }).then(function (bytes) {
    var url = URL.createObjectURL(new Blob([bytes], { type: "image/jpeg" }));
    objectUrls.push(url);
    return url;
  });
  p.then(null, function () { pageUrls.delete(file); });  // let a failed download be retried
  pageUrls.set(file, p);
  return p;
}

// "ניתוק" in the top bar: forget this device entirely (key pair and data key) and start over.
function disconnect() {
  var revoke = function () {
    objectUrls.forEach(function (u) { try { URL.revokeObjectURL(u); } catch (e) { /* ignore */ } });
    objectUrls = [];
    pageUrls = new Map();
    location.reload();
  };
  recordDelete().then(revoke, revoke);
}

function open() {
  return fetchBytes(manifest.snapshot, true).then(function (blob) {
    return decryptText(key, manifest.snapshot, blob);
  }).then(function (text) {
    var bundle = JSON.parse(text);
    bundle.generated_at = manifest.generated_at;
    bundle.title = bundle.title || manifest.title;
    stopPolling();
    id("gate").hidden = true;
    id("app").hidden = false;
    window.MedView.boot(bundle, loadPage, { lock: disconnect, lockLabel: "ניתוק" });
  });
}

/* --- the device record --- */

function newRecord() {
  var rec = null;
  return generateDeviceKey().then(function (pair) {
    rec = { id: RECORD_ID, privateKey: pair.privateKey, publicRaw: pair.publicRaw, devId: null,
            dataKey: null, keyId: null, approvedOnce: false };
    return deviceId(pair.publicRaw);
  }).then(function (devId) {
    rec.devId = devId;
    record = rec;
    return saveRecord();
  }).then(function () { return rec; });
}
function saveRecord() {
  return recordPut(record).then(null, function () { /* private mode: the record lives in memory only */ });
}
function loadRecord() {
  return recordGet().then(function (rec) {
    if (rec && rec.privateKey && rec.publicRaw && rec.devId) { record = rec; return rec; }
    return newRecord();   // none yet, or the passphrase-era record: start fresh
  }, function () { return newRecord(); });
}

/* --- pending: polling until the PC lists this device --- */

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}
function startPolling() {
  stopPolling();
  pollTimer = setInterval(function () {
    fetchManifest().then(function (m) {
      if (!pollTimer) { return; }
      var entry = m.devices[record.devId];
      if (!entry) { return; }
      stopPolling();
      manifest = m;
      setErr("");
      approved(entry, true);
    }, function () { /* still offline or not approved: try again on the next tick */ });
  }, POLL_MS);
}

function showPendingOrRevoked(msg) {
  showGate(record.approvedOnce ? "revoked" : "pending", msg);
  startPolling();
}

/* --- approved: unwrap, verify, open --- */

function approved(entry, useCached) {
  setErr("");
  setBusy(true);
  if (useCached && record.dataKey && record.keyId === manifest.key_id) {
    key = record.dataKey;
    return open().then(null, function () {
      key = null;
      return approved(entry, false);   // the cached key no longer opens the snapshot: unwrap afresh
    });
  }
  var k = null;
  return unwrapDataKey(record.privateKey, manifest.pc_key, record.devId, entry.wrapped).then(function (unwrapped) {
    k = unwrapped;
    return verifyKey(k);
  }, function () {
    var e = new Error("unwrap failed"); e.keyMismatch = true; throw e;
  }).then(function (ok) {
    if (!ok) { var e = new Error("verify failed"); e.keyMismatch = true; throw e; }
    key = k;
    record.dataKey = k;
    record.keyId = manifest.key_id;
    record.approvedOnce = true;
    return saveRecord();
  }).then(open).then(null, function (err) {
    key = null;
    if (err && err.keyMismatch) {
      record.approvedOnce = true;   // it was listed: a fresh request is the only way forward
      showGate("revoked", KEY_MISMATCH_MSG);
      startPolling();
      return;
    }
    showOffline(OFFLINE_MSG);
  });
}

// No usable manifest or snapshot right now: a never-approved phone can still share its request
// code; an approved one only gets the message. Polling resumes either way.
function showOffline(msg) {
  showGate(record.approvedOnce ? "none" : "pending", msg);
  startPolling();
}

/* --- buttons --- */

function currentCode() { return record ? requestCode(record.publicRaw) : ""; }

function flashStatus(msg) {
  setStatus(msg);
  if (statusTimer) { clearTimeout(statusTimer); }
  statusTimer = setTimeout(function () { statusTimer = null; setStatus(WAITING_MSG); }, 2000);
}
function copyCode() {
  var code = currentCode();
  if (!code) { return; }
  var done = function () { flashStatus("הועתק"); };
  var fallback = function () {
    try {
      var node = id("req-code");
      var range = document.createRange();
      range.selectNodeContents(node);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      var ok = document.execCommand("copy");
      sel.removeAllRanges();
      if (ok) { done(); } else { flashStatus("לא הצלחנו להעתיק, סמנו את הקוד והעתיקו ידנית"); }
    } catch (e) { flashStatus("לא הצלחנו להעתיק, סמנו את הקוד והעתיקו ידנית"); }
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(code).then(done, fallback);
  } else {
    fallback();
  }
}
function shareCode() {
  var code = currentCode();
  if (!code) { return; }
  if (navigator.share) {
    var p;
    try { p = navigator.share({ text: "קוד בקשה ל-" + SITE_TITLE + ":\n" + code }); } catch (e) { p = Promise.reject(e); }
    p.then(null, function (err) {
      if (err && err.name === "AbortError") { return; }   // the user closed the share sheet
      copyCode();
    });
  } else {
    copyCode();
  }
}
function requestAgain() {
  setBusy(true);
  setErr("");
  stopPolling();
  key = null;
  recordDelete().then(null, function () {}).then(newRecord).then(function () {
    showGate("pending", "");
    startPolling();
  }, function () {
    setBusy(false);
    setErr("לא הצלחנו ליצור מפתח חדש");
  });
}

function start() {
  id("req-share").addEventListener("click", shareCode);
  id("req-copy").addEventListener("click", copyCode);
  id("req-again").addEventListener("click", requestAgain);
  if ("serviceWorker" in navigator) {
    try { navigator.serviceWorker.register("sw.js").then(null, function () {}); } catch (e) { /* ignore */ }
  }
  setBusy(true);
  if (!subtle) { showGate("none", "הדפדפן לא נתמך"); return; }
  loadRecord().then(function () {
    return fetchManifest().then(function (m) {
      manifest = m;
      var entry = m.devices[record.devId];
      if (!entry) { showPendingOrRevoked(""); return; }
      return approved(entry, true);
    }, function (err) {
      manifest = null;
      if (err && err.badVersion) { showGate("none", BAD_VERSION_MSG); return; }
      // Unreachable and nothing cached: the request code can still be shared; keep polling.
      showOffline(record.dataKey ? OFFLINE_MSG : NO_NET_MSG);
    });
  }).then(null, function (err) {
    setBusy(false);
    setErr(err && err.message === "WebCrypto is not available" ? "הדפדפן לא נתמך" : "שגיאה בפתיחת הדף");
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start);
} else {
  start();
}
})();
