const CACHE = 'ea-admin-v15';
const STATIC = ['/enes-admin/icon-192.png', '/enes-admin/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(STATIC)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
      .then(() => {
        // Tüm açık pencerelere "yenile" mesajı gönder
        return self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      })
      .then(clients => {
        clients.forEach(client => client.postMessage({ type: 'SW_UPDATED', version: CACHE }));
      })
  );
});

// SKIP_WAITING mesajını dinle
self.addEventListener('message', e => {
  if (e.data?.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);

  // HTML ve version.json: her zaman network'ten, asla cache'leme
  if (url.pathname.endsWith('.html') || url.pathname.endsWith('/') || url.pathname.endsWith('version.json')) {
    e.respondWith(fetch(e.request, { cache: 'no-cache' }).catch(() => caches.match(e.request)));
    return;
  }

  // Görseller: cache-first
  if (/\.(png|jpg|svg|webp)$/.test(url.pathname)) {
    e.respondWith(
      caches.match(e.request).then(r => r || fetch(e.request).then(res => {
        caches.open(CACHE).then(c => c.put(e.request, res.clone()));
        return res;
      }))
    );
    return;
  }

  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});
