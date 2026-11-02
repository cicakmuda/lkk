/* Brankas — boot.js: terapkan tema sebelum halaman tampil (mencegah kedip). */
(function () {
  try {
    var p = JSON.parse(localStorage.getItem('bk.prefs') || '{}');
    var t = p.theme || 'auto';
    if (t === 'auto') t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.dataset.theme = t;
  } catch (e) { document.documentElement.dataset.theme = 'light'; }
})();
