/* ==================================================================
   Brankas — app.js
   Penyimpan email, password & catatan rahasia dengan enkripsi end-to-end.

   KEAMANAN (ringkas):
   - Master password → PBKDF2-SHA256 (600.000 putaran) → kunci pembungkus.
   - Kunci brankas acak 256-bit, dibungkus AES-256-GCM, disimpan di sheet "Meta".
   - Setiap item dienkripsi AES-256-GCM dengan IV acak; ID item dipakai sebagai
     "additional data" sehingga baris tidak bisa ditukar-tukar.
   - Kunci brankas hanya ada di memori saat terbuka, dihapus saat terkunci.
   - PIN: kunci brankas dibungkus dengan (PIN + pepper dari server). Server hanya
     memberi pepper jika PIN benar, dan menghapusnya setelah 5x salah.
   ================================================================== */
'use strict';

const APP_VERSION = '1.0.0';
const K = { cfg: 'bk.cfg', cache: 'bk.cache', prefs: 'bk.prefs', pin: 'bk.pin', device: 'bk.device' };
const ITER = 600000;                       // putaran PBKDF2 untuk master password
const PIN_ITER = 100000;                   // putaran PBKDF2 untuk PIN (+ pepper server)
const MASTER_EVERY = 14 * 864e5;           // master password diminta ulang tiap 14 hari
const IDLE_LOCK = 5 * 60e3;                // kunci otomatis jika tidak disentuh 5 menit

/* ---------------- Utilitas ---------------- */
const ls = {
  get(k, fb = null) { try { const v = localStorage.getItem(k); return v == null ? fb : JSON.parse(v); } catch (e) { return fb; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { } },
  del(k) { try { localStorage.removeItem(k); } catch (e) { } }
};
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const pad = n => String(n).padStart(2, '0');
const fmtDT = iso => { try { return new Date(iso).toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' }); } catch (e) { return ''; } };
const hostOf = u => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return ''; } };
const normUrl = u => { u = String(u || '').trim(); if (!u) return ''; return /^[a-z][a-z0-9+.-]*:/i.test(u) ? u : 'https://' + u; };
const isWeb = u => /^https?:\/\//i.test(u || '');
const PALETTE = ['#6366f1', '#0ea5e9', '#10b981', '#f59e0b', '#ef4444', '#ec4899', '#8b5cf6', '#14b8a6', '#64748b', '#0d0d0d'];
const colorOf = s => { let h = 0; for (const ch of String(s).toLowerCase()) h = (h * 31 + ch.codePointAt(0)) >>> 0; return PALETTE[h % PALETTE.length]; };
const initialOf = s => (String(s).match(/[\p{L}\p{N}]/u) || ['?'])[0];

/* ---------------- Ikon ---------------- */
const IC = {
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  settings: '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M9.9 4.2A10 10 0 0 1 12 4c6.5 0 10 7 10 7a17 17 0 0 1-2.2 3.2M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6"/><path d="M14.1 14.1a3 3 0 0 1-4.2-4.2M2 2l20 20"/>',
  star: '<path d="m12 2 3.1 6.3 6.9 1-5 4.9 1.2 6.8L12 17.8 5.8 21l1.2-6.8-5-4.9 6.9-1z"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
  external: '<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
  note: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h5"/>',
  trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1L5 6"/>',
  edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  alert: '<circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/>',
  chevron: '<path d="m9 18 6-6-6-6"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  db: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/><path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/>',
  backspace: '<path d="M21 5H9l-6 7 6 7h12a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1z"/><path d="m17 9-6 6M11 9l6 6"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>'
};
const icon = (n, s = 20) => `<svg class="ic" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${IC[n] || ''}</svg>`;
const starFill = s => `<svg class="ic" width="${s}" height="${s}" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">${IC.star}</svg>`;

/* ==================================================================
   KRIPTOGRAFI (Web Crypto API bawaan browser)
   ================================================================== */
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = buf => { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
const hexs = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const genId = () => 'i' + hexs(rnd(10));

async function pbkdf2(secret, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(key, bytes, aad) {
  const iv = rnd(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, bytes);
  return 'v1:' + b64(iv) + ':' + b64(ct);
}
async function unseal(key, str, aad) {
  const [v, iv, ct] = String(str).split(':');
  if (v !== 'v1' || !iv || !ct) throw new Error('format');
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv), additionalData: enc.encode(aad) }, key, unb64(ct)));
}
const importDek = raw => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);

async function wrapMeta(raw, master) {
  const salt = rnd(16);
  const kek = await pbkdf2(master, salt, ITER);
  return { format: 'brankas-1', kdf: 'PBKDF2-SHA256', iter: ITER, salt: b64(salt), wrapped: await seal(kek, raw, 'brankas-dek'), created: new Date().toISOString() };
}
async function unwrapMeta(meta, master) {
  try { return await unseal(await pbkdf2(master, unb64(meta.salt), Number(meta.iter)), meta.wrapped, 'brankas-dek'); }
  catch (e) { return null; }
}

/** Perkiraan kekuatan password: 0–4. */
function strength(pw) {
  if (!pw) return 0;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(r => r.test(pw)).length;
  let s = 0;
  if (pw.length >= 10) s++;
  if (pw.length >= 14) s++;
  if (classes >= 3 || (pw.length >= 16 && /[\s\-_.]/.test(pw))) s++;
  if (pw.length >= 18 || (classes === 4 && pw.length >= 12)) s++;
  if (/(.)\1{3,}/.test(pw) || /(password|qwerty|123456|abcdef|brankas|admin|iloveyou)/i.test(pw)) s = Math.min(s, 1);
  return Math.min(s, 4);
}
const STRENGTH_LABEL = ['', 'Lemah', 'Cukup', 'Kuat', 'Sangat kuat'];

/* ---------------- State ---------------- */
const V = { raw: null, key: null };           // kunci brankas — HANYA di memori
const S = {
  cfg: ls.get(K.cfg),
  meta: null, rows: [], items: [], broken: 0,
  unlocked: false, view: 'vault', filter: 'all', q: '',
  loading: false, lastSync: null, sheetName: '', syncError: null,
  prefs: Object.assign({ theme: 'auto', lockAfter: 60, masterAt: 0, pinAsked: false }, ls.get(K.prefs, {})),
  hiddenAt: 0, lastAct: Date.now()
};
const savePrefs = () => ls.set(K.prefs, S.prefs);
const saveCache = () => ls.set(K.cache, { meta: S.meta, rows: S.rows, lastSync: S.lastSync, sheetName: S.sheetName });
function loadCache() {
  const c = ls.get(K.cache);
  if (!c) return;
  S.meta = c.meta || null; S.rows = c.rows || []; S.lastSync = c.lastSync || null; S.sheetName = c.sheetName || '';
}

/* ==================================================================
   API ke Google Apps Script
   ================================================================== */
const apiError = (message, extra) => Object.assign(new Error(message), extra || {});
async function apiRaw(url, key, action, payload = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 30000);
  let res;
  try {
    res = await fetch(url, {
      method: 'POST', redirect: 'follow', signal: ctrl.signal, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer',
      headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      body: JSON.stringify({ action, key, payload })
    });
  } catch (e) {
    throw apiError(navigator.onLine ? 'Tidak dapat terhubung ke server.' : 'Kamu sedang offline.', { offline: true });
  } finally { clearTimeout(timer); }
  let json;
  try { json = await res.json(); }
  catch (e) { throw apiError('Respons server tidak valid. Periksa URL Web App & pastikan aksesnya "Siapa saja".', { code: 'BAD_RESPONSE' }); }
  if (!json.ok) throw apiError(json.error || 'Terjadi kesalahan di server.', { code: json.code });
  return json.data;
}
function api(action, payload) {
  if (!S.cfg?.api) return Promise.reject(apiError('Belum terhubung ke spreadsheet.', { code: 'SETUP' }));
  return apiRaw(S.cfg.api, S.cfg.key, action, payload);
}

/* ==================================================================
   DATA BRANKAS
   ================================================================== */
function applyServer(data) {
  if (data.meta) S.meta = data.meta;
  S.rows = data.items || [];
  S.lastSync = new Date().toISOString(); S.sheetName = data.spreadsheet || S.sheetName; S.syncError = null;
  saveCache();
}
async function decryptAll() {
  const items = []; let broken = 0;
  for (const row of S.rows) {
    try { items.push({ ...JSON.parse(dec.decode(await unseal(V.key, row.data, row.id))), id: row.id, updated: row.updated }); }
    catch (e) { broken++; }
  }
  S.items = items; S.broken = broken; sortItems();
}
function sortItems() { S.items.sort((a, b) => String(a.name).localeCompare(String(b.name), 'id', { sensitivity: 'base' })); }

async function refresh({ silent = false } = {}) {
  if (!S.unlocked || S.loading) return;
  S.loading = true; renderTopbar();
  try {
    applyServer(await api('list'));
    if (S.unlocked) await decryptAll();
  } catch (e) {
    S.syncError = e.message;
    if (!silent || e.code === 'AUTH') toast(e.offline ? 'warn' : 'error', e.offline ? 'Offline — menampilkan data tersimpan di HP.' : (e.code === 'AUTH' ? 'Kunci akses ditolak. Periksa di Pengaturan → Koneksi.' : 'Gagal memuat: ' + e.message));
  } finally {
    S.loading = false;
    if (S.unlocked) render();
  }
}

async function saveItem(item, existing) {
  const now = new Date().toISOString();
  const body = { type: item.type, name: item.name, user: item.user, pass: item.pass, url: item.url, note: item.note, fav: !!item.fav, created: existing?.created || now, changed: now };
  const data = await seal(V.key, enc.encode(JSON.stringify(body)), item.id);
  const res = await api('put', { id: item.id, data, base: existing ? existing.updated : '' });
  const row = { id: item.id, data, updated: res.updated };
  const ri = S.rows.findIndex(r => r.id === item.id); if (ri >= 0) S.rows[ri] = row; else S.rows.push(row);
  const full = { ...body, id: item.id, updated: res.updated };
  const ii = S.items.findIndex(x => x.id === item.id); if (ii >= 0) S.items[ii] = full; else S.items.push(full);
  sortItems(); saveCache();
  return full;
}
async function removeItem(it) {
  await api('delete', { id: it.id });
  S.rows = S.rows.filter(r => r.id !== it.id); S.items = S.items.filter(x => x.id !== it.id);
  saveCache();
}

/* ==================================================================
   PIN PER-PERANGKAT
   ================================================================== */
function deviceId() { let d = ls.get(K.device); if (!d) { d = 'd' + hexs(rnd(12)); ls.set(K.device, d); } return d; }
const Pin = {
  rec() { return ls.get(K.pin); },
  has() { const r = ls.get(K.pin); return !!(r && r.wrapped && S.cfg); },
  async verifier(pin, salt) { return hexs(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode('brankas-pin-verify:' + salt + ':' + pin)))); },
  key(pin, pepper, salt) { return pbkdf2(pin, enc.encode(pepper + ':' + salt), PIN_ITER); },
  async enable(pin) {
    if (!V.raw) throw apiError('Brankas terkunci.');
    const device = deviceId(), salt = hexs(rnd(16));
    const { pepper } = await api('pinRegister', { device, verifier: await this.verifier(pin, salt) });
    const wrapped = await seal(await this.key(pin, pepper, salt), V.raw, 'brankas-pin:' + device);
    ls.set(K.pin, { device, salt, wrapped });
  },
  async unlock(pin) {
    const r = this.rec();
    const { pepper } = await api('pinUnlock', { device: r.device, verifier: await this.verifier(pin, r.salt) });
    try { return await unseal(await this.key(pin, pepper, r.salt), r.wrapped, 'brankas-pin:' + r.device); }
    catch (e) { throw apiError('PIN di HP ini tidak berlaku lagi. Masuk dengan master password.', { code: 'PIN_GONE' }); }
  },
  forget() { ls.del(K.pin); },
  async disable() { const r = this.rec(); if (r) { try { await api('pinRemove', { device: r.device }); } catch (e) { } } this.forget(); },
  weak(pin) { return /^(\d)\1{3}$/.test(pin) || ['1234', '4321', '0123', '3210', '6789', '9876', '1212', '1122', '2580', '0852'].includes(pin); }
};
const masterFresh = () => Date.now() - (S.prefs.masterAt || 0) < MASTER_EVERY;

/* ==================================================================
   BUKA & KUNCI
   ================================================================== */
async function openVault(raw) {
  V.raw = raw; V.key = await importDek(raw);
  S.unlocked = true; S.lastAct = Date.now();
  await decryptAll();
  document.documentElement.classList.remove('gated');
  S.view = 'vault';
  render();
  refresh({ silent: true });
}

function lock() {
  if (!S.unlocked) return;
  if (V.raw) V.raw.fill(0);
  V.raw = null; V.key = null;
  S.items = []; S.unlocked = false; S.q = '';
  sheets.splice(0).forEach(s => s.el.remove());
  $$('.lock').forEach(e => e.remove());
  document.documentElement.classList.add('gated');
  $$('.view').forEach(v => { v.innerHTML = ''; });
  gateUnlock();
}

function gateUnlock(msg) {
  if (Pin.has() && masterFresh()) return gatePin(msg);
  return gateMaster(msg || (Pin.has() ? 'Demi keamanan, master password diminta ulang setiap 14 hari.' : ''));
}

/* ---------------- Layar gerbang ---------------- */
function gate(html) {
  closeGate();
  const el = document.createElement('div');
  el.className = 'gate';
  el.innerHTML = `<div class="gate-in">${html}</div>`;
  document.body.appendChild(el);
  return el;
}
function closeGate() { $$('.gate').forEach(g => g.remove()); }
const pwField = (id, ph, ac = 'current-password') => `<div class="pw"><input class="input" id="${id}" type="password" placeholder="${esc(ph)}" autocomplete="${ac}" autocapitalize="off" autocorrect="off" spellcheck="false"><button type="button" class="eye" data-eye="${id}" aria-label="Tampilkan">${icon('eye', 20)}</button></div>`;
function bindEyes(root) {
  root.addEventListener('click', e => {
    const b = e.target.closest('[data-eye]'); if (!b) return;
    const inp = $('#' + b.dataset.eye, root); const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password'; b.innerHTML = icon(show ? 'eyeOff' : 'eye', 20);
  });
}
function bindStrength(root, inputId, boxId) {
  const box = $('#' + boxId, root);
  const paint = () => { const s = strength($('#' + inputId, root).value); box.className = 's' + s; $('.strength-label', box).textContent = STRENGTH_LABEL[s] ? 'Kekuatan: ' + STRENGTH_LABEL[s] : ''; };
  $('#' + inputId, root).addEventListener('input', paint); paint();
}
const strengthBox = id => `<div id="${id}"><div class="strength"><i></i><i></i><i></i><i></i></div><div class="strength-label"></div></div>`;
function busy(btn, label) { btn.disabled = true; btn.dataset.label = btn.textContent; btn.innerHTML = `<span class="spinner"></span>${esc(label)}`; }
function unbusy(btn) { btn.disabled = false; btn.textContent = btn.dataset.label || 'OK'; }
function validNewMaster(pw, pw2) {
  if (pw.length < 10) return 'Minimal 10 karakter.';
  if (strength(pw) < 2) return 'Terlalu mudah ditebak. Gunakan kalimat panjang atau campuran huruf, angka & simbol.';
  if (pw !== pw2) return 'Ulangi master password tidak sama.';
  return '';
}

/* 1) Hubungkan ke Apps Script */
function gateConnect({ cancel = false } = {}) {
  document.documentElement.classList.add('gated');
  const c = S.cfg || {};
  const el = gate(`<div class="logo">${icon('shield', 30)}</div>
    <h1>Hubungkan Brankas</h1>
    <p class="lead">Tempel URL Web App dan Kunci Akses dari Apps Script spreadsheet Brankas-mu. Cukup sekali di HP ini.</p>
    <div class="field"><label for="g-url">URL Web App</label><input class="input" id="g-url" placeholder="https://script.google.com/macros/s/…/exec" value="${esc(c.api || '')}" autocomplete="off" autocapitalize="off" spellcheck="false"></div>
    <div class="field"><label for="g-key">Kunci Akses</label><input class="input" id="g-key" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" autocomplete="off" autocapitalize="characters" spellcheck="false">
      <div class="hint">Di spreadsheet: menu 🔐 Brankas → Lihat kunci akses.</div></div>
    <div class="err" id="g-err"></div>
    <button class="btn primary block lg" id="g-go">Hubungkan</button>
    ${cancel ? '<button class="btn ghost block" id="g-cancel" style="margin-top:8px">Batal</button>' : ''}`);
  $('#g-cancel', el)?.addEventListener('click', () => { closeGate(); document.documentElement.classList.remove('gated'); });
  $('#g-go', el).addEventListener('click', async () => {
    const url = $('#g-url', el).value.trim(), key = $('#g-key', el).value.trim(), err = $('#g-err', el), go = $('#g-go', el);
    err.textContent = '';
    if (!/^https:\/\/script\.google(usercontent)?\.com\/.+\/exec(\?.*)?$/.test(url)) { err.textContent = 'URL harus diawali https://script.google.com/macros/s/… dan berakhiran /exec'; return; }
    if (key.replace(/[^A-Za-z0-9]/g, '').length < 16) { err.textContent = 'Kunci akses belum lengkap.'; return; }
    busy(go, 'Menghubungkan…');
    try {
      const info = await apiRaw(url, key, 'ping');
      if (S.unlocked) lockSilently();
      Pin.forget();
      S.cfg = { api: url, key }; ls.set(K.cfg, S.cfg);
      S.meta = null; S.rows = []; ls.del(K.cache); S.prefs.pinAsked = false; savePrefs();
      if (!info.initialized) return gateCreate();
      try { applyServer(await api('list')); } catch (e) { }
      gateMaster('', true);
    } catch (e) {
      err.textContent = e.code === 'AUTH' ? 'Kunci akses salah. Salin ulang dari menu 🔐 Brankas → Lihat kunci akses.'
        : e.offline ? 'Tidak bisa terhubung. Pastikan internet aktif, URL benar, dan akses Web App "Siapa saja".' : e.message;
      unbusy(go);
    }
  });
}
function lockSilently() { if (V.raw) V.raw.fill(0); V.raw = null; V.key = null; S.items = []; S.unlocked = false; sheets.splice(0).forEach(s => s.el.remove()); $$('.view').forEach(v => { v.innerHTML = ''; }); }

/* 2) Buat brankas baru (master password) */
function gateCreate() {
  const el = gate(`<div class="logo">${icon('key', 30)}</div>
    <h1>Buat master password</h1>
    <p class="lead">Master password adalah kunci utama brankasmu. Semua data dienkripsi dengannya sebelum keluar dari HP.</p>
    <div class="notice warn"><b>Wajib diingat:</b> master password tidak disimpan di mana pun. Jika lupa, isi brankas <b>tidak bisa dipulihkan</b> oleh siapa pun.
      <ul><li>Minimal 10 karakter. Lebih panjang lebih aman.</li><li>Tips: gabungkan 4 kata acak, mis. <i>kopi-hujan-sepeda-77</i>.</li><li>Jangan pakai password yang sama dengan akun lain.</li></ul></div>
    <div class="field"><label for="g-pw">Master password</label>${pwField('g-pw', 'Buat master password', 'new-password')}${strengthBox('g-st')}</div>
    <div class="field"><label for="g-pw2">Ulangi master password</label>${pwField('g-pw2', 'Ketik ulang', 'new-password')}</div>
    <label class="check"><input type="checkbox" id="g-ok"><span>Saya paham: jika lupa master password, data di brankas hilang permanen.</span></label>
    <div class="err" id="g-err"></div>
    <button class="btn primary block lg" id="g-go">Buat brankas</button>`);
  bindEyes(el); bindStrength(el, 'g-pw', 'g-st');
  $('#g-go', el).addEventListener('click', async () => {
    const pw = $('#g-pw', el).value, pw2 = $('#g-pw2', el).value, err = $('#g-err', el), go = $('#g-go', el);
    err.textContent = validNewMaster(pw, pw2);
    if (!err.textContent && !$('#g-ok', el).checked) err.textContent = 'Centang pernyataan di atas untuk melanjutkan.';
    if (err.textContent) return;
    busy(go, 'Mengamankan brankas…');
    try {
      const raw = rnd(32);
      const meta = await wrapMeta(raw, pw);
      await api('init', { meta });
      S.meta = meta; S.rows = []; saveCache();
      S.prefs.masterAt = Date.now(); savePrefs();
      closeGate();
      await openVault(raw);
      toast('success', 'Brankas siap dipakai');
      setTimeout(offerPin, 500);
    } catch (e) {
      if (e.code === 'EXISTS') { try { applyServer(await api('list')); } catch (x) { } return gateMaster('Brankas sudah pernah dibuat. Buka dengan master password-mu.', true); }
      err.textContent = e.offline ? 'Tidak bisa terhubung. Periksa internet.' : e.message; unbusy(go);
    }
  });
}

/* 3) Buka dengan master password */
function gateMaster(msg = '', first = false) {
  document.documentElement.classList.add('gated');
  const el = gate(`<div class="logo">${icon('lock', 30)}</div>
    <h1>${first ? 'Masukkan master password' : 'Buka Brankas'}</h1>
    <p class="lead">${first ? 'Brankas ditemukan. Masukkan master password untuk membukanya di HP ini.' : 'Masukkan master password untuk membuka.'}</p>
    ${msg ? `<div class="notice">${esc(msg)}</div>` : ''}
    <div class="field">${pwField('g-pw', 'Master password')}</div>
    <div class="err" id="g-err"></div>
    <button class="btn primary block lg" id="g-go">Buka</button>
    <button class="link" id="g-forgot">Lupa master password?</button>`);
  bindEyes(el);
  const inp = $('#g-pw', el);
  setTimeout(() => inp.focus(), 80);
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') $('#g-go', el).click(); });
  $('#g-forgot', el).addEventListener('click', () => infoDialog('Master password tidak bisa dipulihkan',
    'Brankas memakai enkripsi end-to-end: tidak ada salinan master password di mana pun, termasuk di spreadsheet. Coba ingat-ingat variasi yang biasa kamu pakai. Jika benar-benar lupa, satu-satunya jalan adalah membuat brankas baru (lihat panduan: "Mulai ulang brankas"); isi lama tidak bisa dibuka.'));
  $('#g-go', el).addEventListener('click', async () => {
    const pw = inp.value, err = $('#g-err', el), go = $('#g-go', el);
    err.textContent = '';
    if (!pw) { err.textContent = 'Master password wajib diisi.'; return; }
    busy(go, 'Membuka…');
    try { applyServer(await api('list')); } catch (e) {
      if (e.code === 'AUTH') { err.textContent = 'Kunci akses ditolak. Hubungkan ulang HP ini.'; unbusy(go); return setTimeout(() => gateConnect(), 1500); }
    }
    if (!S.meta) { err.textContent = 'Tidak bisa terhubung ke spreadsheet. Periksa internet.'; unbusy(go); return; }
    const raw = await unwrapMeta(S.meta, pw);
    if (!raw) {
      await new Promise(r => setTimeout(r, 600));
      err.textContent = 'Master password salah.'; shake(inp.parentElement); inp.select(); unbusy(go); return;
    }
    S.prefs.masterAt = Date.now(); savePrefs();
    closeGate();
    await openVault(raw);
    if (!Pin.has()) setTimeout(offerPin, 500);
  });
}

/* 4) Buka cepat dengan PIN */
async function gatePin(msg) {
  closeGate();
  document.documentElement.classList.add('gated');
  const r = await pinScreen({
    title: 'Masukkan PIN', sub: msg || 'Brankas terkunci', left: 'Master password',
    onPin: async pin => {
      try {
        const raw = await Pin.unlock(pin);
        await openVault(raw);
        return true;
      } catch (e) {
        if (e.code === 'PIN_GONE') { Pin.forget(); return { close: 'gone:' + e.message }; }
        if (e.offline) return 'Butuh internet untuk PIN. Gunakan master password.';
        if (e.code === 'AUTH') return { close: 'auth' };
        return e.message;
      }
    }
  });
  if (r === null) return gateMaster();
  if (typeof r === 'string' && r.startsWith('gone:')) return gateMaster(r.slice(5));
  if (r === 'auth') { toast('error', 'Kunci akses ditolak. Hubungkan ulang HP ini.'); return gateConnect(); }
}

/** Layar keypad PIN. onPin → true | 'pesan' | {title,sub,msg} | {close:v} */
function pinScreen({ title, sub = '', left = '', onPin }) {
  return new Promise(resolve => {
    const el = document.createElement('div');
    el.className = 'lock';
    el.setAttribute('role', 'dialog'); el.setAttribute('aria-modal', 'true');
    el.innerHTML = `<div class="lock-in">
      <div class="logo sm">${icon('lock', 24)}</div>
      <h2 class="lk-title"></h2><p class="lk-sub"></p>
      <div class="pin-dots">${'<i></i>'.repeat(4)}</div>
      <div class="pin-msg" aria-live="assertive"></div>
      <div class="keypad">${[1, 2, 3, 4, 5, 6, 7, 8, 9].map(n => `<button data-k="${n}">${n}</button>`).join('')}
        <button class="kp-text" data-k="left">${esc(left)}</button><button data-k="0">0</button>
        <button class="kp-text" data-k="del" aria-label="Hapus angka">${icon('backspace', 26)}</button></div></div>`;
    document.body.appendChild(el);
    const dots = $('.pin-dots', el), msg = $('.pin-msg', el);
    const head = (t, s) => { $('.lk-title', el).textContent = t; $('.lk-sub', el).textContent = s || ''; };
    head(title, sub);
    let val = '', busyNow = false;
    const paint = () => $$('i', dots).forEach((d, i) => d.classList.toggle('on', i < val.length));
    const fail = text => { msg.textContent = text; dots.classList.add('err'); shake(dots); try { navigator.vibrate && navigator.vibrate([30, 40, 30]); } catch (e) { } };
    const close = v => { document.removeEventListener('keydown', onKey); el.classList.add('out'); setTimeout(() => el.remove(), 220); resolve(v); };
    const press = async k => {
      if (busyNow || !el.isConnected) return;
      if (k === 'left') { if (left) close(null); return; }
      if (k === 'del') { val = val.slice(0, -1); paint(); return; }
      if (val.length >= 4) return;
      val += k; msg.textContent = ''; dots.classList.remove('err', 'ok'); paint();
      if (val.length < 4) return;
      busyNow = true; msg.textContent = '';
      const r = await onPin(val);
      if (r === true) { dots.classList.add('ok'); setTimeout(() => close(val), 160); return; }
      if (r && typeof r === 'object' && 'close' in r) return close(r.close);
      if (r && typeof r === 'object') { head(r.title, r.sub); if (r.msg) fail(r.msg); }
      else fail(r || 'PIN salah');
      setTimeout(() => { val = ''; paint(); busyNow = false; }, 350);
    };
    el.addEventListener('click', e => { const b = e.target.closest('[data-k]'); if (b) press(b.dataset.k); });
    const onKey = e => { if (/^\d$/.test(e.key)) { e.preventDefault(); press(e.key); } else if (e.key === 'Backspace') press('del'); };
    document.addEventListener('keydown', onKey);
  });
}

async function setupPin() {
  if (!navigator.onLine) return toast('warn', 'Butuh internet untuk mengaktifkan PIN.');
  let first = null;
  const intro = { title: 'Buat PIN', sub: 'PIN 4 angka untuk membuka brankas di HP ini' };
  const ok = await pinScreen({
    ...intro, left: 'Batal',
    onPin: async pin => {
      if (!first) {
        if (Pin.weak(pin)) return 'PIN terlalu mudah ditebak. Pilih kombinasi lain.';
        first = pin;
        return { title: 'Ulangi PIN', sub: 'Masukkan PIN yang sama sekali lagi' };
      }
      if (pin !== first) { first = null; return { ...intro, msg: 'PIN tidak sama. Ulangi dari awal.' }; }
      try { await Pin.enable(pin); return true; }
      catch (e) { first = null; return { ...intro, msg: e.offline ? 'Butuh internet untuk mengaktifkan PIN.' : e.message }; }
    }
  });
  if (ok) toast('success', 'PIN aktif di HP ini');
  if (S.view === 'settings') renderSettings();
}
function offerPin() {
  if (!S.unlocked || Pin.has() || S.prefs.pinAsked) return;
  S.prefs.pinAsked = true; savePrefs();
  openSheet({
    cls: 'dialog',
    html: `<div class="dialog-body"><div class="art" style="background:var(--surface);color:var(--text)">${icon('lock', 22)}</div><h3>Buka cepat dengan PIN?</h3>
      <p>Pakai PIN 4 angka sehari-hari. Master password tetap diminta tiap 14 hari. Salah PIN 5 kali, PIN di HP ini otomatis nonaktif.</p></div>
      <div class="dialog-actions"><button class="btn secondary" data-close>Nanti</button><button class="btn primary" data-ok>Aktifkan</button></div>`,
    onMount: s => $('[data-ok]', s.el).addEventListener('click', async () => { await s.close(); setupPin(); })
  });
}

/* ==================================================================
   UI: toast, sheet, dialog
   ================================================================== */
function toast(type, msg, ms = 2600) {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  const ic = { success: icon('check', 14), error: icon('x', 14), warn: '!' }[type] || '';
  el.innerHTML = `<span class="t-ic">${ic}</span><span class="t-msg">${esc(msg)}</span>`;
  $('#toasts').appendChild(el);
  const ctl = {
    update(t, m, d = 2600) { el.className = 'toast ' + t; el.querySelector('.t-ic').innerHTML = { success: icon('check', 14), error: icon('x', 14), warn: '!' }[t] || ''; el.querySelector('.t-msg').textContent = m; ctl.hideIn(d); },
    hide() { el.classList.add('out'); setTimeout(() => el.remove(), 260); },
    hideIn(d) { clearTimeout(ctl.t); ctl.t = setTimeout(ctl.hide, d); }
  };
  if (type !== 'loading') ctl.hideIn(ms);
  el.addEventListener('click', ctl.hide);
  return ctl;
}

const sheets = [];
let popIgnore = 0, popResolve = null;
function openSheet({ title = '', html, foot = '', cls = '', onMount, onClose }) {
  const wrap = document.createElement('div');
  wrap.className = 'sheet-wrap ' + cls;
  wrap.innerHTML = `<div class="sheet-backdrop"></div><div class="sheet" role="dialog" aria-modal="true">
    ${cls.includes('dialog') ? '' : '<div class="sheet-handle"></div>'}
    ${title ? `<div class="sheet-head"><h3>${esc(title)}</h3><button class="icon-btn" data-close aria-label="Tutup">${icon('x', 18)}</button></div>` : ''}
    <div class="sheet-body">${html}</div>${foot ? `<div class="sheet-foot">${foot}</div>` : ''}</div>`;
  document.body.appendChild(wrap);
  requestAnimationFrame(() => requestAnimationFrame(() => wrap.classList.add('open')));
  const sh = { el: wrap, onClose, close: fromPop => closeSheet(sh, fromPop) };
  wrap.addEventListener('click', e => { if (e.target.classList.contains('sheet-backdrop') || e.target.closest('[data-close]')) sh.close(); });
  enableDrag(sh);
  sheets.push(sh);
  history.pushState({ sheet: sheets.length }, '');
  onMount && onMount(sh);
  return sh;
}
function closeSheet(sh, fromPop) {
  const i = sheets.indexOf(sh);
  if (i < 0) return Promise.resolve();
  sheets.splice(i, 1);
  sh.el.classList.remove('open');
  setTimeout(() => sh.el.remove(), 320);
  sh.onClose && sh.onClose();
  if (fromPop) return Promise.resolve();
  return new Promise(res => { popIgnore++; popResolve = res; history.back(); setTimeout(() => { if (popResolve === res) { popResolve = null; res(); } }, 400); });
}
window.addEventListener('popstate', () => {
  if (popIgnore > 0) { popIgnore--; const r = popResolve; popResolve = null; r && r(); return; }
  const t = sheets[sheets.length - 1];
  if (t) t.close(true);
});
document.addEventListener('keydown', e => { if (e.key === 'Escape' && sheets.length) sheets[sheets.length - 1].close(); });
function enableDrag(sh) {
  const sheet = $('.sheet', sh.el), grip = $('.sheet-handle', sh.el), head = $('.sheet-head', sh.el);
  if (!grip) return;
  let y0 = null, dy = 0;
  const start = e => { y0 = e.touches[0].clientY; dy = 0; sheet.style.transition = 'none'; };
  const move = e => { if (y0 == null) return; dy = Math.max(0, e.touches[0].clientY - y0); sheet.style.transform = `translateY(${dy}px)`; };
  const end = () => { if (y0 == null) return; sheet.style.transition = ''; sheet.style.transform = ''; if (dy > 90) sh.close(); y0 = null; };
  [grip, head].forEach(el => { if (!el) return; el.addEventListener('touchstart', start, { passive: true }); el.addEventListener('touchmove', move, { passive: true }); el.addEventListener('touchend', end); });
}
function confirmDialog({ title, message, ok = 'Hapus', cancel = 'Batal', danger = true, ic = 'trash' }) {
  return new Promise(resolve => {
    let result = false;
    openSheet({
      cls: 'dialog',
      html: `<div class="dialog-body"><div class="art">${icon(ic, 22)}</div><h3>${esc(title)}</h3><p>${esc(message)}</p></div>
             <div class="dialog-actions"><button class="btn secondary" data-close>${esc(cancel)}</button><button class="btn ${danger ? 'danger' : 'primary'}" data-ok>${esc(ok)}</button></div>`,
      onClose: () => resolve(result),
      onMount: s => $('[data-ok]', s.el).addEventListener('click', () => { result = true; s.close(); })
    });
  });
}
function infoDialog(title, message) {
  openSheet({ cls: 'dialog', html: `<div class="dialog-body"><div class="art" style="background:var(--surface);color:var(--text)">${icon('alert', 22)}</div><h3>${esc(title)}</h3><p>${esc(message)}</p></div>
    <div class="dialog-actions" style="grid-template-columns:1fr"><button class="btn primary" data-close>Mengerti</button></div>` });
}
function shake(el) { el.classList.remove('shake'); void el.offsetWidth; el.classList.add('shake'); }

/* ---------------- Salin ke clipboard ---------------- */
let clipTimer = null;
async function copy(text, label) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    toast('success', `${label} disalin · dihapus dari clipboard dalam 30 detik`);
    clearTimeout(clipTimer);
    clipTimer = setTimeout(() => { if (document.hasFocus()) navigator.clipboard.writeText('').catch(() => { }); }, 30000);
  } catch (e) { toast('error', 'Gagal menyalin. Tampilkan lalu salin manual.'); }
}

/* ==================================================================
   RENDER
   ================================================================== */
function syncLabel() {
  if (S.loading) return 'Menyinkronkan…';
  if (S.syncError) return '<span class="sync-dot err"></span>Belum tersinkron';
  if (S.lastSync) { const d = new Date(S.lastSync); return `<span class="sync-dot"></span>Tersinkron ${pad(d.getHours())}.${pad(d.getMinutes())}`; }
  return '';
}
function renderTopbar() {
  if (!S.unlocked) return;
  $('#topbar').innerHTML = `<div class="tb-text"><h1>${S.view === 'settings' ? 'Pengaturan' : 'Brankas'}</h1><div class="sub">${S.items.length} item · ${syncLabel()}</div></div>
    <button class="icon-btn ${S.loading ? 'spin' : ''}" data-action="refresh" aria-label="Sinkronkan">${icon('refresh', 18)}</button>
    <button class="icon-btn" data-action="lock" aria-label="Kunci">${icon('lock', 18)}</button>`;
}
function render() {
  if (!S.unlocked) return;
  renderTopbar();
  $$('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.nav === S.view));
  $$('.view').forEach(v => v.classList.toggle('active', v.dataset.view === S.view));
  (S.view === 'settings' ? renderSettings : renderVault)();
}
function navigate(view) { if (S.view === view) { window.scrollTo({ top: 0, behavior: 'smooth' }); return; } S.view = view; window.scrollTo(0, 0); render(); }

/* ---------- Daftar brankas ---------- */
function renderVault() {
  const el = $('[data-view="vault"]');
  const n = { all: S.items.length, login: S.items.filter(i => i.type === 'login').length, note: S.items.filter(i => i.type === 'note').length };
  el.innerHTML = `<div class="search">${icon('search', 18)}<input class="input" id="q" type="search" placeholder="Cari nama, email, atau link…" value="${esc(S.q)}" autocomplete="off" autocapitalize="off" spellcheck="false"></div>
    <div class="chips">${[['all', 'Semua'], ['login', 'Login'], ['note', 'Catatan']].map(([k, l]) => `<button class="chip ${S.filter === k ? 'active' : ''}" data-filter="${k}">${l}<span class="count">${n[k]}</span></button>`).join('')}</div>
    ${S.broken ? `<div class="banner" style="margin-top:12px">${icon('alert', 18)}<span><b>${S.broken} item tidak bisa dibuka.</b> Kemungkinan data di sheet diubah manual.</span></div>` : ''}
    <div id="list"></div>`;
  renderList();
}
function filtered() {
  const q = S.q.trim().toLowerCase();
  return S.items.filter(i => (S.filter === 'all' || i.type === S.filter) &&
    (!q || [i.name, i.user, i.url, i.note].some(v => String(v || '').toLowerCase().includes(q))));
}
function itemRow(it, i) {
  const note = it.type === 'note';
  const sub = note ? 'Catatan rahasia' : (it.user || hostOf(it.url) || 'Tanpa username');
  return `<div class="item" data-item="${esc(it.id)}" role="button" tabindex="0" style="animation-delay:${Math.min(i, 12) * 16}ms">
    <span class="avatar ${note ? 'note' : ''}" style="background:${colorOf(it.name)}">${note ? icon('note', 20) : esc(initialOf(it.name))}</span>
    <span class="main"><b><span>${esc(it.name)}</span>${it.fav ? `<span class="star">${starFill(13)}</span>` : ''}</b><small>${esc(sub)}</small></span>
    ${!note && it.pass ? `<button class="quick" data-copy-pass="${esc(it.id)}" aria-label="Salin password">${icon('copy', 19)}</button>` : `<span class="quick" style="color:var(--muted)">${icon('chevron', 18)}</span>`}
  </div>`;
}
function renderList() {
  const box = $('#list'); if (!box) return;
  if (!S.items.length) {
    box.innerHTML = `<div class="empty"><div class="art">${icon('shield', 34)}</div><h4>Brankas masih kosong</h4>
      <p>Simpan email & password pertamamu. Semuanya dienkripsi sebelum keluar dari HP ini.</p>
      <button class="btn primary" data-action="add">${icon('plus', 18)}Tambah item</button></div>`;
    return;
  }
  const list = filtered();
  if (!list.length) { box.innerHTML = `<div class="empty"><div class="art">${icon('search', 34)}</div><h4>Tidak ditemukan</h4><p>Coba kata kunci lain.</p></div>`; return; }
  const favs = list.filter(i => i.fav);
  const showFav = favs.length && !S.q.trim();
  box.innerHTML = (showFav ? `<div class="section-head"><h2>Favorit</h2></div><div class="tx-list">${favs.map(itemRow).join('')}</div>` : '') +
    `<div class="section-head"><h2>${S.q.trim() ? list.length + ' hasil' : (S.filter === 'note' ? 'Catatan' : S.filter === 'login' ? 'Login' : 'Semua item')}</h2></div>
     <div class="tx-list">${list.map(itemRow).join('')}</div>`;
}

/* ---------- Pengaturan ---------- */
function renderSettings() {
  const el = $('[data-view="settings"]');
  if (!el.classList.contains('active')) return;
  const c = S.cfg || {};
  el.innerHTML = `
    <div class="lg-title">Brankas</div>
    <div class="list-group">
      <div class="row">${icon('shield')}<div class="grow"><b>${S.items.length} item tersimpan</b><small>Terenkripsi AES-256-GCM di HP sebelum dikirim</small></div><span class="secure-badge">${icon('check', 13)}Aman</span></div>
    </div>
    <div class="lg-title">Keamanan</div>
    <div class="list-group">
      <div class="row wrap">${icon('clock')}<div class="grow"><b>Kunci otomatis</b><small>Setelah aplikasi ditinggal</small></div>
        <div class="seg sm">${[[0, 'Segera'], [60, '1 mnt'], [300, '5 mnt']].map(([s, l]) => `<button class="${S.prefs.lockAfter === s ? 'active' : ''}" data-lock-after="${s}">${l}</button>`).join('')}</div></div>
      ${Pin.has()
        ? `<button class="row btn-row" data-action="pin-change">${icon('lock')}<div class="grow"><b>Ganti PIN</b><small>PIN aktif di HP ini</small></div>${icon('chevron', 18)}</button>
           <button class="row btn-row danger" data-action="pin-off">${icon('x')}<div class="grow"><b>Matikan PIN di HP ini</b></div></button>`
        : `<button class="row btn-row" data-action="pin-on">${icon('lock')}<div class="grow"><b>Aktifkan PIN</b><small>Buka cepat dengan 4 angka</small></div>${icon('chevron', 18)}</button>`}
      <button class="row btn-row" data-action="master-change">${icon('key')}<div class="grow"><b>Ganti master password</b></div>${icon('chevron', 18)}</button>
      <button class="row btn-row" data-action="lock">${icon('lock')}<div class="grow"><b>Kunci sekarang</b></div>${icon('chevron', 18)}</button>
    </div>
    <div class="lg-title">Koneksi</div>
    <div class="list-group">
      <div class="row">${icon('db')}<div class="grow"><b>${esc(S.sheetName || 'Google Sheets')}</b><small>${esc((c.api || '').replace(/^https:\/\//, '').slice(0, 34))}…</small></div></div>
      <button class="row btn-row" data-action="refresh">${icon('refresh')}<div class="grow"><b>Sinkronkan sekarang</b><small>${S.lastSync ? 'Terakhir ' + esc(fmtDT(S.lastSync)) : 'Belum pernah'}${S.syncError ? ' · ' + esc(S.syncError) : ''}</small></div>${icon('chevron', 18)}</button>
      <button class="row btn-row" data-action="connect">${icon('link')}<div class="grow"><b>Ganti URL / kunci akses</b></div>${icon('chevron', 18)}</button>
      <button class="row btn-row danger" data-action="disconnect">${icon('logout')}<div class="grow"><b>Putuskan HP ini</b><small>Data di spreadsheet tidak terhapus</small></div></button>
    </div>
    <div class="lg-title">Tampilan</div>
    <div class="list-group"><div class="row">${icon('sun')}<div class="grow"><b>Tema</b></div>
      <div class="seg sm">${[['auto', 'Otomatis'], ['light', 'Terang'], ['dark', 'Gelap']].map(([k, l]) => `<button class="${S.prefs.theme === k ? 'active' : ''}" data-theme-set="${k}">${l}</button>`).join('')}</div></div></div>
    <p class="muted" style="text-align:center;font-size:12px;margin:20px 0">Brankas v${APP_VERSION}</p>`;
}

/* ---------- Detail item ---------- */
function openDetail(id) {
  const it = S.items.find(x => x.id === id); if (!it) return;
  const note = it.type === 'note';
  const field = (key, label, value, { secret = false, copyable = true, pre = false, link = false } = {}) => !value ? '' :
    `<div class="f"><div class="fv"><small>${esc(label)}</small><div class="${secret ? 'mono' : ''} ${pre ? 'pre' : ''}" data-val="${key}">${secret ? '••••••••••' : esc(value)}</div></div>
      ${secret ? `<button class="act" data-reveal="${key}" aria-label="Tampilkan">${icon('eye', 19)}</button>` : ''}
      ${link && isWeb(value) ? `<a class="act" href="${esc(value)}" target="_blank" rel="noopener noreferrer" aria-label="Buka link">${icon('external', 19)}</a>` : ''}
      ${copyable ? `<button class="act" data-copy="${key}" aria-label="Salin ${esc(label)}">${icon('copy', 19)}</button>` : ''}</div>`;
  openSheet({
    title: note ? 'Catatan rahasia' : 'Detail login',
    html: `<div class="d-head"><span class="avatar lg ${note ? 'note' : ''}" style="background:${colorOf(it.name)}">${note ? icon('note', 26) : esc(initialOf(it.name))}</span>
        <div style="min-width:0"><h4>${esc(it.name)} ${it.fav ? `<span class="star" style="color:#f59e0b">${starFill(15)}</span>` : ''}</h4><small>${note ? 'Catatan rahasia' : esc(hostOf(it.url) || 'Akun login')}</small></div></div>
      <div class="fields">${note ? field('note', 'Isi catatan', it.note, { pre: true }) :
        field('user', 'Email / username', it.user) + field('pass', 'Password', it.pass, { secret: true }) + field('url', 'Link', it.url, { link: true }) + field('note', 'Catatan', it.note, { pre: true, copyable: false })}</div>
      <div class="d-meta">Diperbarui ${esc(fmtDT(it.changed || it.updated))}</div>`,
    foot: `<div class="actions-2"><button class="btn secondary" data-del>${icon('trash', 18)}Hapus</button><button class="btn primary" data-edit>${icon('edit', 18)}Edit</button></div>`,
    onMount: s => {
      const labels = { user: 'Email/username', pass: 'Password', url: 'Link', note: note ? 'Catatan' : 'Catatan' };
      s.el.addEventListener('click', e => {
        const c = e.target.closest('[data-copy]'); if (c) return copy(it[c.dataset.copy], labels[c.dataset.copy]);
        const r = e.target.closest('[data-reveal]');
        if (r) {
          const v = $(`[data-val="${r.dataset.reveal}"]`, s.el), show = r.dataset.shown !== '1';
          v.textContent = show ? it[r.dataset.reveal] : '••••••••••'; r.dataset.shown = show ? '1' : '';
          r.innerHTML = icon(show ? 'eyeOff' : 'eye', 19);
        }
      });
      $('[data-edit]', s.el).addEventListener('click', async () => { await s.close(); openForm(S.items.find(x => x.id === id)); });
      $('[data-del]', s.el).addEventListener('click', async () => {
        await s.close();
        if (!await confirmDialog({ title: `Hapus "${it.name}"?`, message: 'Item dipindah ke sheet "Arsip" dalam bentuk terenkripsi, jadi masih bisa dipulihkan dari spreadsheet.' })) return;
        const t = toast('loading', 'Menghapus…');
        try { await removeItem(it); t.update('success', 'Item dihapus & diarsipkan'); render(); }
        catch (e) { t.update('error', e.offline ? 'Butuh internet untuk menghapus.' : 'Gagal menghapus: ' + e.message, 4500); }
      });
    }
  });
}

/* ---------- Tambah / edit ---------- */
function openForm(existing) {
  const isNew = !existing;
  const f = existing ? { ...existing } : { id: genId(), type: S.filter === 'note' ? 'note' : 'login', name: '', user: '', pass: '', url: '', note: '', fav: false };
  openSheet({
    title: isNew ? 'Tambah item' : 'Edit item',
    html: `${isNew ? `<div class="seg" id="f-type" style="margin-bottom:16px">${[['login', 'Login'], ['note', 'Catatan rahasia']].map(([k, l]) => `<button data-type="${k}">${l}</button>`).join('')}</div>` : ''}
      <div id="f-body"></div><div class="field-err" id="f-err" style="text-align:left"></div>`,
    foot: `<button class="btn primary block lg" id="f-save">${isNew ? 'Simpan' : 'Simpan perubahan'}</button>`,
    onMount: s => {
      const root = s.el;
      const collect = () => { $$('[data-f]', root).forEach(i => { f[i.dataset.f] = i.value; }); };
      const paint = () => {
        $$('#f-type button', root).forEach(b => b.classList.toggle('active', b.dataset.type === f.type));
        const login = f.type === 'login';
        $('#f-body', root).innerHTML = login ? `
          <div class="field"><label>Nama layanan</label><input class="input" data-f="name" maxlength="80" placeholder="Contoh: Gmail, Instagram, BCA" autocomplete="off" value="${esc(f.name)}"></div>
          <div class="field"><label>Email / username</label><input class="input" data-f="user" maxlength="200" placeholder="nama@email.com" autocomplete="off" autocapitalize="off" spellcheck="false" inputmode="email" value="${esc(f.user)}"></div>
          <div class="field"><label>Password</label><div class="pw"><input class="input" id="f-pass" data-f="pass" type="password" maxlength="500" placeholder="Password akun" autocomplete="new-password" autocapitalize="off" spellcheck="false" value="${esc(f.pass)}"><button type="button" class="eye" data-eye="f-pass" aria-label="Tampilkan">${icon('eye', 20)}</button></div></div>
          <div class="field"><label>Link <span class="muted">(opsional)</span></label><input class="input" data-f="url" maxlength="500" placeholder="contoh: mail.google.com" autocomplete="off" autocapitalize="off" spellcheck="false" inputmode="url" value="${esc(f.url)}"></div>
          <div class="field"><label>Catatan <span class="muted">(opsional)</span></label><textarea class="input" data-f="note" maxlength="2000" placeholder="Mis. pertanyaan keamanan, kode cadangan" style="min-height:84px">${esc(f.note)}</textarea></div>`
          : `
          <div class="field"><label>Judul</label><input class="input" data-f="name" maxlength="80" placeholder="Contoh: PIN ATM, Kode pemulihan" autocomplete="off" value="${esc(f.name)}"></div>
          <div class="field"><label>Isi catatan</label><textarea class="input" data-f="note" maxlength="5000" placeholder="Tulis catatan rahasiamu…" style="min-height:180px">${esc(f.note)}</textarea></div>`;
        $('#f-body', root).insertAdjacentHTML('beforeend', `<button class="chip fav-toggle ${f.fav ? 'active' : ''}" id="f-fav">${f.fav ? starFill(16) : icon('star', 16)}Favorit</button>`);
      };
      paint();
      bindEyes(root);
      root.addEventListener('click', e => {
        const t = e.target.closest('[data-type]');
        if (t && t.dataset.type !== f.type) { collect(); f.type = t.dataset.type; paint(); return; }
        if (e.target.closest('#f-fav')) { collect(); f.fav = !f.fav; paint(); }
      });
      if (isNew) setTimeout(() => $('[data-f="name"]', root)?.focus(), 60);
      $('#f-save', root).addEventListener('click', async () => {
        collect();
        const err = $('#f-err', root); err.textContent = '';
        f.name = f.name.trim(); f.user = (f.user || '').trim(); f.url = normUrl(f.url);
        if (!f.name) err.textContent = f.type === 'login' ? 'Nama layanan wajib diisi.' : 'Judul wajib diisi.';
        else if (f.type === 'login' && !f.user && !f.pass) err.textContent = 'Isi email/username atau password.';
        else if (f.type === 'note' && !f.note.trim()) err.textContent = 'Isi catatan wajib diisi.';
        if (err.textContent) { shake(err); return; }
        if (f.type === 'note') { f.user = ''; f.pass = ''; f.url = ''; }
        const btn = $('#f-save', root); busy(btn, 'Mengenkripsi & menyimpan…');
        try {
          await saveItem(f, existing);
          await s.close();
          toast('success', isNew ? 'Tersimpan & terenkripsi' : 'Perubahan tersimpan');
          render();
        } catch (e) {
          unbusy(btn);
          err.textContent = e.offline ? 'Butuh internet untuk menyimpan. Data belum tersimpan.' : e.message;
          if (e.code === 'CONFLICT' || e.code === 'NOT_FOUND') refresh({ silent: true });
        }
      });
    }
  });
}

/* ---------- Ganti master password ---------- */
function openMasterChange() {
  openSheet({
    title: 'Ganti master password',
    html: `<div class="notice">Isi brankas tidak perlu dienkripsi ulang. PIN di HP ini tetap berlaku. HP lain akan diminta master password baru.</div>
      <div class="field"><label>Master password saat ini</label>${pwField('m-cur', 'Master password saat ini')}</div>
      <div class="field"><label>Master password baru</label>${pwField('m-new', 'Minimal 10 karakter', 'new-password')}${strengthBox('m-st')}</div>
      <div class="field"><label>Ulangi master password baru</label>${pwField('m-new2', 'Ketik ulang', 'new-password')}</div>
      <div class="field-err" id="m-err" style="text-align:left"></div>`,
    foot: `<button class="btn primary block lg" id="m-save">Ganti master password</button>`,
    onMount: s => {
      const root = s.el; bindEyes(root); bindStrength(root, 'm-new', 'm-st');
      $('#m-save', root).addEventListener('click', async () => {
        const cur = $('#m-cur', root).value, nw = $('#m-new', root).value, nw2 = $('#m-new2', root).value, err = $('#m-err', root), btn = $('#m-save', root);
        err.textContent = validNewMaster(nw, nw2);
        if (!err.textContent && nw === cur) err.textContent = 'Master password baru harus berbeda.';
        if (err.textContent) return;
        busy(btn, 'Memproses…');
        try {
          applyServer(await api('list'));
          const raw = await unwrapMeta(S.meta, cur);
          if (!raw) { err.textContent = 'Master password saat ini salah.'; unbusy(btn); return; }
          raw.fill(0);
          const meta = await wrapMeta(V.raw, nw);
          await api('setMeta', { meta, expect: S.meta.wrapped });
          S.meta = { ...meta, created: S.meta.created }; saveCache();
          S.prefs.masterAt = Date.now(); savePrefs();
          await s.close();
          toast('success', 'Master password diganti. Jangan sampai lupa!', 4000);
        } catch (e) { unbusy(btn); err.textContent = e.offline ? 'Butuh internet untuk mengganti master password.' : e.message; }
      });
    }
  });
}

/* ==================================================================
   TEMA
   ================================================================== */
const mql = matchMedia('(prefers-color-scheme: dark)');
function applyTheme() {
  const t = S.prefs.theme === 'auto' ? (mql.matches ? 'dark' : 'light') : S.prefs.theme;
  document.documentElement.dataset.theme = t;
  $('meta[name="theme-color"]').setAttribute('content', t === 'dark' ? '#000000' : '#ffffff');
}
mql.addEventListener?.('change', () => { if (S.prefs.theme === 'auto') applyTheme(); });

/* ==================================================================
   EVENT GLOBAL
   ================================================================== */
document.addEventListener('click', async e => {
  if (!S.unlocked || e.target.closest('.sheet-wrap,.gate,.lock')) return;
  const cp = e.target.closest('[data-copy-pass]');
  if (cp) { const it = S.items.find(x => x.id === cp.dataset.copyPass); return it && copy(it.pass, 'Password ' + it.name); }
  const el = e.target.closest('[data-nav],[data-action],[data-item],[data-filter],[data-theme-set],[data-lock-after]');
  if (!el) return;
  const d = el.dataset;
  if (d.nav) return navigate(d.nav);
  if (d.item) return openDetail(d.item);
  if (d.filter) { S.filter = d.filter; return renderVault(); }
  if (d.themeSet) { S.prefs.theme = d.themeSet; savePrefs(); applyTheme(); return renderSettings(); }
  if (d.lockAfter !== undefined) { S.prefs.lockAfter = Number(d.lockAfter); savePrefs(); return renderSettings(); }
  switch (d.action) {
    case 'add': return openForm();
    case 'refresh': return refresh();
    case 'lock': return lock();
    case 'pin-on': case 'pin-change': return setupPin();
    case 'pin-off':
      if (await confirmDialog({ title: 'Matikan PIN?', message: 'Setelah ini, membuka brankas di HP ini selalu memakai master password.', ok: 'Matikan', ic: 'lock' })) {
        await Pin.disable(); toast('success', 'PIN dimatikan'); renderSettings();
      }
      return;
    case 'master-change': return openMasterChange();
    case 'connect': return gateConnect({ cancel: true });
    case 'disconnect':
      if (await confirmDialog({ title: 'Putuskan HP ini?', message: 'Semua data Brankas di HP ini dihapus dan PIN dinonaktifkan. Isi brankas di spreadsheet tetap aman.', ok: 'Putuskan', ic: 'logout' })) {
        await Pin.disable();
        [K.cfg, K.cache].forEach(ls.del);
        S.cfg = null; S.meta = null; S.rows = []; S.prefs.pinAsked = false; S.prefs.masterAt = 0; savePrefs();
        lockSilently(); gateConnect();
      }
  }
});
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target.matches?.('[data-item]')) openDetail(e.target.dataset.item);
});
document.addEventListener('input', e => { if (e.target.id === 'q') { S.q = e.target.value; renderList(); } });

/* ---------- Kunci otomatis ---------- */
['pointerdown', 'keydown', 'touchstart'].forEach(ev => document.addEventListener(ev, () => { S.lastAct = Date.now(); }, { passive: true, capture: true }));
setInterval(() => { if (S.unlocked && Date.now() - S.lastAct > IDLE_LOCK) lock(); }, 10000);
document.addEventListener('visibilitychange', () => {
  const root = document.documentElement;
  if (document.visibilityState === 'hidden') {
    S.hiddenAt = Date.now();
    if (S.unlocked) { root.classList.add('privacy'); if (S.prefs.lockAfter === 0) lock(); }
    return;
  }
  root.classList.remove('privacy');
  if (S.unlocked && S.hiddenAt && Date.now() - S.hiddenAt >= S.prefs.lockAfter * 1000) lock();
  else if (S.unlocked && (!S.lastSync || Date.now() - new Date(S.lastSync).getTime() > 60e3)) refresh({ silent: true });
});
window.addEventListener('pagehide', () => { if (S.unlocked && S.prefs.lockAfter === 0) lock(); });

/* ==================================================================
   MULAI
   ================================================================== */
function init() {
  $$('[data-icon]').forEach(el => { el.outerHTML = icon(el.dataset.icon, el.dataset.icon === 'plus' ? 26 : 22); });
  applyTheme();
  if (!window.crypto?.subtle) { gate(`<h1>Browser tidak didukung</h1><p class="lead">Buka Brankas lewat HTTPS di Chrome atau Safari versi terbaru.</p>`); return; }
  if (!S.cfg) return gateConnect();
  loadCache();
  gateUnlock();
  if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => { });
}
init();
