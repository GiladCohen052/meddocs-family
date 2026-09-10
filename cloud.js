/* The encrypted family site: fetch the plaintext manifest, derive the AES key from the family
 * passphrase (PBKDF2-SHA256, WebCrypto), verify it, cache the non-extractable CryptoKey in
 * IndexedDB, decrypt the snapshot and hand it to MedView. Page images are decrypted on demand
 * into object URLs. Plain ES5 + Promises: iOS 15 Safari is the target.
 *
 * Blob layout (must match app/server/cloud.py): nonce(12) || AES-256-GCM ciphertext || tag(16),
 * with the blob's manifest path (e.g. "data/snapshot.bin") as the additional authenticated data.
 *
 * window.MedCloud = { deriveKey, decryptBlob, splitBlob } - the pure helpers, also run under node.
 */
(function () {
"use strict";

var MANIFEST_URL = "data/manifest.json";
var VERIFY_TEXT = "meddocs-family-v1";
var DB_NAME = "meddocs-family";
var STORE = "keys";
var RECORD_ID = "main";

var subtle = typeof crypto !== "undefined" && crypto.subtle ? crypto.subtle : null;

function utf8(s) { return new TextEncoder().encode(String(s)); }
function b64decode(s) {
  var bin = atob(String(s).replace(/\s+/g, ""));
  var out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
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

// passphrase + base64 salt + iterations -> non-extractable AES-GCM CryptoKey (decrypt only).
// PBKDF2-HMAC-SHA256 to 512 bits; the first 32 bytes are the AES key, the rest is the server's
// nonce key and is discarded here.
function deriveKey(passphrase, saltB64, iterations) {
  if (!subtle) { return Promise.reject(new Error("WebCrypto is not available")); }
  return subtle.importKey("raw", utf8(passphrase), "PBKDF2", false, ["deriveBits"])
    .then(function (base) {
      return subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: b64decode(saltB64),
                                 iterations: Number(iterations) }, base, 512);
    })
    .then(function (bits) {
      var aes = new Uint8Array(bits).slice(0, 32);
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
  var parts;
  try { parts = splitBlob(blob); } catch (e) { return Promise.reject(e); }
  return subtle.decrypt({ name: "AES-GCM", iv: parts.nonce, additionalData: utf8(path), tagLength: 128 },
                        key, parts.body)
    .then(function (pt) { return new Uint8Array(pt); });
}

if (typeof window !== "undefined") {
  window.MedCloud = { deriveKey: deriveKey, decryptBlob: decryptBlob, splitBlob: splitBlob };
}

if (typeof document === "undefined") { return; }  // node: only the helpers above

/* ---------- key cache (IndexedDB) ---------- */

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
function cacheGet() { return withStore("readonly", function (s) { return s.get(RECORD_ID); }); }
function cachePut(key, salt) {
  return withStore("readwrite", function (s) { return s.put({ id: RECORD_ID, key: key, salt: salt }); });
}
function cacheDelete() { return withStore("readwrite", function (s) { return s.delete(RECORD_ID); }); }

/* ---------- boot flow ---------- */

var manifest = null;
var key = null;
var pageUrls = new Map();   // snapshot file -> Promise<object URL>
var objectUrls = [];        // everything to revoke on lock

function id(name) { return document.getElementById(name); }
function setErr(msg) { id("lock-err").textContent = msg || ""; }
function setBusy(on) {
  id("lock-busy").hidden = !on;
  id("unlock").disabled = !!on;
  id("pass").disabled = !!on;
}
function showLock(msg) {
  id("app").hidden = true;
  id("lock").hidden = false;
  setBusy(false);
  setErr(msg || "");
  try { id("pass").focus(); } catch (e) { /* not focusable yet */ }
}

var OFFLINE_MSG = "אין חיבור לאינטרנט וההעתק המקומי חסר";

function fetchBytes(url, noStore) {
  return fetch(url, noStore ? { cache: "no-store" } : undefined).then(function (r) {
    if (!r.ok) { throw new Error("HTTP " + r.status + " for " + url); }
    return r.arrayBuffer();
  }).then(toBytes);
}
function fetchManifest() {
  return fetch(MANIFEST_URL, { cache: "no-store" }).then(function (r) {
    if (!r.ok) { throw new Error("HTTP " + r.status + " for manifest"); }
    return r.json();
  }).then(function (m) {
    if (!m || !m.kdf || !m.kdf.salt || !m.snapshot || !m.verify) { throw new Error("bad manifest"); }
    m.pages = m.pages || {};
    return m;
  });
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

function lock() {
  var revoke = function () {
    objectUrls.forEach(function (u) { try { URL.revokeObjectURL(u); } catch (e) { /* ignore */ } });
    objectUrls = [];
    pageUrls = new Map();
    location.reload();
  };
  cacheDelete().then(revoke, revoke);
}

function open() {
  return fetchBytes(manifest.snapshot, true).then(function (blob) {
    return decryptText(key, manifest.snapshot, blob);
  }).then(function (text) {
    var bundle = JSON.parse(text);
    bundle.generated_at = manifest.generated_at;
    bundle.title = bundle.title || manifest.title;
    id("lock").hidden = true;
    id("app").hidden = false;
    window.MedView.boot(bundle, loadPage, { lock: lock });
  });
}

function unlock() {
  var pass = id("pass").value || "";
  if (!pass) { setErr("הקלידו את הסיסמה"); return; }
  setErr("");
  setBusy(true);
  var k = null;
  deriveKey(pass, manifest.kdf.salt, manifest.kdf.iterations).then(function (derived) {
    k = derived;
    return verifyKey(k);
  }).then(function (ok) {
    if (!ok) { showLock("סיסמה שגויה"); return; }
    key = k;
    var cached = cachePut(k, manifest.kdf.salt).then(null, function () { /* private mode: no cache */ });
    return cached.then(open).then(null, function () {
      key = null;
      showLock(OFFLINE_MSG);
    });
  }).then(null, function () {
    showLock(OFFLINE_MSG);
  });
}

// A cached key is only trusted when it was derived from the manifest's current salt; a new salt
// means the passphrase was changed on the PC.
function cachedKeyFor(m) {
  return cacheGet().then(function (rec) {
    if (!rec || !rec.key) { return null; }
    if (rec.salt !== m.kdf.salt) {
      return cacheDelete().then(null, function () {}).then(function () {
        showLock("הסיסמה הוחלפה, הקלידו את החדשה");
        return null;
      });
    }
    return rec.key;
  }, function () { return null; });
}

function start() {
  id("unlock").addEventListener("click", unlock);
  id("pass").addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.keyCode === 13) { e.preventDefault(); unlock(); }
  });
  if ("serviceWorker" in navigator) {
    try { navigator.serviceWorker.register("sw.js").then(null, function () {}); } catch (e) { /* ignore */ }
  }
  setBusy(true);
  fetchManifest().then(function (m) {
    manifest = m;
    return cachedKeyFor(m);
  }).then(function (k) {
    if (!k) { if (!id("lock-err").textContent) { showLock(""); } else { setBusy(false); } return; }
    key = k;
    return open().then(null, function () {
      // The cached key no longer opens the snapshot (or the download failed): fall back to the
      // passphrase; an unreadable snapshot with a fresh key is reported there.
      key = null;
      return verifyKey(k).then(function (ok) {
        if (ok) { showLock(OFFLINE_MSG); } else { cacheDelete().then(null, function () {}); showLock("סיסמה שגויה"); }
      }, function () { showLock(OFFLINE_MSG); });
    });
  }).then(null, function () {
    manifest = null;
    id("unlock").disabled = true;
    id("lock-busy").hidden = true;
    id("pass").disabled = false;
    setErr(OFFLINE_MSG);
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start);
} else {
  start();
}
})();
