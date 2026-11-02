/* Brankas — Service Worker (sw.js)
   Menyimpan file aplikasi agar bisa dibuka offline. TIDAK menyimpan data brankas.
   Naikkan VERSION setiap kali kamu mengunggah perubahan file. */
const VERSION = 'brankas-v1.0.0';
const SHELL = ['./', './index.html', './style.css', './boot.js', './app.js', './manifest.webmanifest',
  './icons/icon-192.png', './icons/icon-512.png', './icons/apple-touch-icon.png', './icons/favicon.svg'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== location.origin) return;   // API & pihak lain: langsung ke jaringan
  e.respondWith((async () => {
    try {
      const res = await fetch(req);
      if (res.ok) (await caches.open(VERSION)).put(req, res.clone());
      return res;
    } catch (err) {
      return (await caches.match(req, { ignoreSearch: true })) ||
        (req.mode === 'navigate' ? caches.match('./index.html') : Response.error());
    }
  })());
});
