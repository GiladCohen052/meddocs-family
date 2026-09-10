/* Service worker for the encrypted family site.
 * Network-first for the shell, data/manifest.json and data/snapshot.bin (an update on the PC
 * shows on the next open; the cached copy answers when offline). Cache-first for data/pages/:
 * a page blob never changes for a given path, pruned pages simply stop being referenced.
 */
var CACHE = "meddocs-family-v1";

self.addEventListener("install", function (e) { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });

self.addEventListener("fetch", function (e) {
  var url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) { return; }
  var cacheFirst = url.pathname.indexOf("/data/pages/") !== -1;
  e.respondWith(caches.open(CACHE).then(function (cache) {
    if (cacheFirst) {
      return cache.match(e.request).then(function (hit) {
        return hit || fetch(e.request).then(function (r) {
          if (r.ok) { cache.put(e.request, r.clone()); }
          return r;
        });
      });
    }
    return fetch(e.request).then(function (r) {
      if (r.ok) { cache.put(e.request, r.clone()); }
      return r;
    }).catch(function () {
      return cache.match(e.request).then(function (hit) { return hit || Response.error(); });
    });
  }));
});
