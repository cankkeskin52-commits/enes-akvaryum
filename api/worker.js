// Enes Akvaryum — Cloudflare Worker API
// Primary: Cloudflare KV  |  Backup: GitHub repo

const KV_KEY    = 'products';
const GH_REPO   = 'cankkeskin52-commits/enes-akvaryum';
const GH_FILE   = 'backup/data.json';
const GH_BRANCH = 'main';

const ALLOWED_ORIGINS = ['https://enesakvaryum.com.tr', 'https://cankkeskin52-commits.github.io'];

function corsHeaders(extra = {}, origin = '') {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin)
    ? origin
    : (origin.includes('localhost') ? origin : ALLOWED_ORIGINS[0]);
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Api-Key, Authorization',
    ...extra
  };
}

function json(data, status = 200, origin = '') {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders({ 'Content-Type': 'application/json' }, origin),
  });
}

// ── JWT (HS256) ─────────────────────────────────────────────────────────────
function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b64urlDecode(s) {
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

async function jwtKey(secret, usages = ['sign', 'verify']) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    usages
  );
}

async function signJWT(payload, env) {
  const secret = env.JWT_SECRET || 'enes-akvaryum-jwt-secret-2024';
  const key = await jwtKey(secret);
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body   = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig    = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${b64url(sig)}`;
}

async function verifyJWT(token, env) {
  try {
    const [header, body, sig] = token.split('.');
    const secret = env.JWT_SECRET || 'enes-akvaryum-jwt-secret-2024';
    const key   = await jwtKey(secret);
    const valid = await crypto.subtle.verify(
      'HMAC', key,
      b64urlDecode(sig),
      new TextEncoder().encode(`${header}.${body}`)
    );
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    if (payload.exp && payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch { return null; }
}

async function verifyAdminJWT(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return false;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const [header, body, sig] = parts;
    const secret = env.JWT_SECRET || 'enes-akvaryum-jwt-secret-2024';
    const key = await jwtKey(secret, ['verify']);
    const valid = await crypto.subtle.verify(
      'HMAC', key,
      b64urlDecode(sig),
      new TextEncoder().encode(`${header}.${body}`)
    );
    if (!valid) return false;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    // 24 saat geçerli
    if (payload.iat && Date.now() - payload.iat > 24 * 60 * 60 * 1000) return false;
    // exp tabanlı token da destekle
    if (payload.exp && payload.exp < Date.now() / 1000) return false;
    return payload.role === 'admin';
  } catch { return false; }
}

// ── Rate limiting ─────────────────────────────────────────────────────────────
async function checkRateLimit(env, ip) {
  const key = `ratelimit:${ip}`;
  const raw = await env.ENES_USERS.get(key);
  const data = raw ? JSON.parse(raw) : { count: 0, reset: Date.now() + 5 * 60 * 1000 };
  if (Date.now() > data.reset) { data.count = 0; data.reset = Date.now() + 5 * 60 * 1000; }
  data.count++;
  await env.ENES_USERS.put(key, JSON.stringify(data), { expirationTtl: 300 });
  return data.count > 5;
}

// ── Şifre (PBKDF2) ───────────────────────────────────────────────────────────
async function hashPassword(password, salt) {
  const km = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 100000, hash: 'SHA-256' },
    km, 256
  );
  return b64url(bits);
}

// ── KV helpers ───────────────────────────────────────────────────────────────
async function getUser(env, email) {
  const raw = await env.ENES_USERS.get(`user:${email}`);
  return raw ? JSON.parse(raw) : null;
}

async function requireAuth(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth?.startsWith('Bearer ')) return null;
  return verifyJWT(auth.slice(7), env);
}

// ── GitHub backup ─────────────────────────────────────────────────────────────
async function backupToGitHub(token, body) {
  try {
    const apiBase = `https://api.github.com/repos/${GH_REPO}/contents/${GH_FILE}`;
    const headers = {
      'Authorization': `token ${token}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
      'User-Agent': 'enes-akvaryum-worker',
    };
    let sha = null;
    const getResp = await fetch(apiBase + `?ref=${GH_BRANCH}`, { headers });
    if (getResp.ok) { const cur = await getResp.json(); sha = cur.sha; }
    const now     = new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' });
    const content = btoa(unescape(encodeURIComponent(body)));
    await fetch(apiBase, {
      method: 'PUT', headers,
      body: JSON.stringify({ message: `🐠 Otomatik yedek — ${now}`, content, branch: GH_BRANCH, ...(sha ? { sha } : {}) }),
    });
  } catch (e) { console.error('GitHub backup failed:', e.message); }
}

// ── Main handler ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const method = request.method.toUpperCase();
    const url    = new URL(request.url);
    const path   = url.pathname;
    const origin = request.headers.get('Origin') || '';

    if (method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders({}, origin) });

    // ── Admin login ──────────────────────────────────────────────────────────
    if (path === '/admin/login' && method === 'POST') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      if (await checkRateLimit(env, ip)) return json({ error: 'Çok fazla deneme. 5 dakika bekleyin.' }, 429, origin);
      const { password } = await request.json().catch(() => ({}));
      const adminPass = env.ADMIN_PASSWORD || 'enesakvaryume2024';
      if (!password || password !== adminPass) {
        return json({ error: 'Hatalı şifre' }, 401, origin);
      }
      const token = await signJWT({ role: 'admin', iat: Date.now(), exp: Math.floor(Date.now() / 1000) + 86400 * 30 }, env);
      return json({ token }, 200, origin);
    }

    // ── Ürünler (eski API — backward compat) ─────────────────────────────────
    if (path === '/' || path === '') {
      if (method === 'GET') {
        const raw  = await env.ENES_DATA.get(KV_KEY);
        const data = raw || JSON.stringify({ fish: [], aquariums: [], reviews: [], plants: [], subscribers: [], visits: 0, plant_products: [], stone_products: [], equipment: [], yemler: [], aksesuarlar: [] });
        return new Response(data, { status: 200, headers: corsHeaders({ 'Content-Type': 'application/json' }, origin) });
      }
      if (method === 'PUT') {
        if (!await verifyAdminJWT(request, env)) return json({ error: 'Unauthorized' }, 401, origin);
        const body = await request.text();
        try { JSON.parse(body); } catch { return json({ error: 'Invalid JSON' }, 400, origin); }
        await env.ENES_DATA.put(KV_KEY, body);
        if (env.GITHUB_TOKEN) ctx.waitUntil(backupToGitHub(env.GITHUB_TOKEN, body));
        return json({ ok: true }, 200, origin);
      }
    }

    // ── Kayıt ────────────────────────────────────────────────────────────────
    if (path === '/auth/register' && method === 'POST') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      if (await checkRateLimit(env, ip)) return json({ error: 'Çok fazla deneme. 5 dakika bekleyin.' }, 429, origin);
      const { email, password, name, phone } = await request.json();
      if (!email || !password || !name) return json({ error: 'Ad, e-posta ve şifre zorunludur' }, 400, origin);
      const em = email.toLowerCase().trim();
      if (await getUser(env, em)) return json({ error: 'Bu e-posta zaten kayıtlı' }, 409, origin);
      const salt         = crypto.randomUUID();
      const passwordHash = await hashPassword(password, salt);
      const user         = { email: em, name: name.trim(), phone: (phone || '').trim(), passwordHash, salt, createdAt: Date.now() };
      await env.ENES_USERS.put(`user:${em}`, JSON.stringify(user));
      // Üye index'ine ekle — admin listesinin eksiksiz olması için (KV list() gecikmesine karşı)
      try {
        const idxRaw = await env.ENES_USERS.get('members:index');
        const idx = idxRaw ? JSON.parse(idxRaw) : [];
        if (!idx.includes(em)) { idx.push(em); await env.ENES_USERS.put('members:index', JSON.stringify(idx)); }
      } catch {}
      const token = await signJWT({ email: em, exp: Math.floor(Date.now() / 1000) + 86400 * 30 }, env);
      return json({ ok: true, token, user: { email: em, name: user.name, phone: user.phone } }, 200, origin);
    }

    // ── Giriş ────────────────────────────────────────────────────────────────
    if (path === '/auth/login' && method === 'POST') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      if (await checkRateLimit(env, ip)) return json({ error: 'Çok fazla deneme. 5 dakika bekleyin.' }, 429, origin);
      const { email, password } = await request.json();
      if (!email || !password) return json({ error: 'E-posta ve şifre zorunludur' }, 400, origin);
      const em   = email.toLowerCase().trim();
      const user = await getUser(env, em);
      if (!user) return json({ error: 'E-posta veya şifre hatalı' }, 401, origin);
      const hash = await hashPassword(password, user.salt);
      if (hash !== user.passwordHash) return json({ error: 'E-posta veya şifre hatalı' }, 401, origin);
      const token = await signJWT({ email: em, exp: Math.floor(Date.now() / 1000) + 86400 * 30 }, env);
      return json({ ok: true, token, user: { email: em, name: user.name, phone: user.phone } }, 200, origin);
    }

    // ── Profil ───────────────────────────────────────────────────────────────
    if (path === '/me' && method === 'GET') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401, origin);
      const user = await getUser(env, payload.email);
      if (!user) return json({ error: 'Kullanıcı bulunamadı' }, 404, origin);
      return json({ email: user.email, name: user.name, phone: user.phone, createdAt: user.createdAt }, 200, origin);
    }

    // ── Profil güncelle ───────────────────────────────────────────────────────
    if (path === '/me' && method === 'PUT') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401, origin);
      const user = await getUser(env, payload.email);
      if (!user) return json({ error: 'Kullanıcı bulunamadı' }, 404, origin);
      const { name, phone } = await request.json();
      if (name) user.name = name.trim();
      if (phone !== undefined) user.phone = phone.trim();
      await env.ENES_USERS.put(`user:${payload.email}`, JSON.stringify(user));
      return json({ ok: true, user: { email: user.email, name: user.name, phone: user.phone } }, 200, origin);
    }

    // ── Şifre değiştir ────────────────────────────────────────────────────────
    if (path === '/me/password' && method === 'PUT') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401, origin);
      const user = await getUser(env, payload.email);
      if (!user) return json({ error: 'Kullanıcı bulunamadı' }, 404, origin);
      const { currentPassword, newPassword } = await request.json();
      if (!currentPassword || !newPassword) return json({ error: 'Mevcut ve yeni şifre zorunludur' }, 400, origin);
      if (newPassword.length < 6) return json({ error: 'Yeni şifre en az 6 karakter olmalıdır' }, 400, origin);
      const checkHash = await hashPassword(currentPassword, user.salt);
      if (checkHash !== user.passwordHash) return json({ error: 'Mevcut şifre hatalı' }, 401, origin);
      const newSalt = crypto.randomUUID();
      user.salt = newSalt;
      user.passwordHash = await hashPassword(newPassword, newSalt);
      await env.ENES_USERS.put(`user:${payload.email}`, JSON.stringify(user));
      return json({ ok: true }, 200, origin);
    }

    // ── Favoriler ────────────────────────────────────────────────────────────
    if (path === '/me/favorites') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401, origin);
      const favKey = `favorites:${payload.email}`;
      if (method === 'GET') {
        const raw = await env.ENES_USERS.get(favKey);
        return json(raw ? JSON.parse(raw) : [], 200, origin);
      }
      if (method === 'POST') {
        const { productId } = await request.json();
        if (!productId) return json({ error: 'productId gerekli' }, 400, origin);
        const raw  = await env.ENES_USERS.get(favKey);
        const favs = raw ? JSON.parse(raw) : [];
        const idx  = favs.indexOf(productId);
        if (idx === -1) favs.push(productId); else favs.splice(idx, 1);
        await env.ENES_USERS.put(favKey, JSON.stringify(favs));
        return json({ ok: true, favorites: favs, added: idx === -1 }, 200, origin);
      }
    }

    // ── Siparişler ───────────────────────────────────────────────────────────
    if (path === '/me/orders' && method === 'GET') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401, origin);
      const raw = await env.ENES_USERS.get(`orders:${payload.email}`);
      return json(raw ? JSON.parse(raw) : [], 200, origin);
    }

    // ── Kampanyalar (herkese açık) ────────────────────────────────────────────
    if (path === '/campaigns' && method === 'GET') {
      const raw = await env.ENES_USERS.get('campaigns');
      return json(raw ? JSON.parse(raw) : [], 200, origin);
    }

    // ── Instagram posts ──────────────────────────────────────────────────────
    if (path === '/instagram' && method === 'GET') {
      const raw = await env.ENES_USERS.get('instagram');
      return json(raw ? JSON.parse(raw) : [], 200, origin);
    }
    if (path === '/admin/instagram') {
      if (!await verifyAdminJWT(request, env)) return json({ error: 'Unauthorized' }, 401, origin);
      if (method === 'GET') {
        const raw = await env.ENES_USERS.get('instagram');
        return json(raw ? JSON.parse(raw) : [], 200, origin);
      }
      if (method === 'PUT') {
        const body = await request.text();
        try { JSON.parse(body); } catch { return json({ error: 'Invalid JSON' }, 400, origin); }
        await env.ENES_USERS.put('instagram', body);
        return json({ ok: true }, 200, origin);
      }
    }

    // ── Admin: Sipariş ekle ──────────────────────────────────────────────────
    if (path === '/admin/orders' && method === 'POST') {
      if (!await verifyAdminJWT(request, env)) return json({ error: 'Unauthorized' }, 401, origin);
      const { email, order } = await request.json();
      if (!email || !order) return json({ error: 'email ve order zorunludur' }, 400, origin);
      const em     = email.toLowerCase().trim();
      const raw    = await env.ENES_USERS.get(`orders:${em}`);
      const orders = raw ? JSON.parse(raw) : [];
      const newOrder = { id: crypto.randomUUID(), ...order, createdAt: Date.now() };
      orders.unshift(newOrder);
      await env.ENES_USERS.put(`orders:${em}`, JSON.stringify(orders));
      return json({ ok: true, order: newOrder }, 200, origin);
    }

    // ── Adresler ─────────────────────────────────────────────────────────────
    if (path === '/me/addresses') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401, origin);
      const key = `addresses:${payload.email}`;
      if (method === 'GET') {
        const raw = await env.ENES_USERS.get(key);
        return json(raw ? JSON.parse(raw) : [], 200, origin);
      }
      if (method === 'POST') {
        const { title, name, phone, city, district, fullAddress } = await request.json();
        if (!title || !fullAddress) return json({ error: 'Başlık ve adres zorunludur' }, 400, origin);
        const raw  = await env.ENES_USERS.get(key);
        const list = raw ? JSON.parse(raw) : [];
        const item = { id: crypto.randomUUID(), title, name: name || '', phone: phone || '', city: city || '', district: district || '', fullAddress, createdAt: Date.now() };
        list.push(item);
        await env.ENES_USERS.put(key, JSON.stringify(list));
        return json({ ok: true, address: item }, 200, origin);
      }
    }
    if (path.startsWith('/me/addresses/') && method === 'DELETE') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401, origin);
      const id  = path.split('/').pop();
      const key = `addresses:${payload.email}`;
      const raw = await env.ENES_USERS.get(key);
      let list  = raw ? JSON.parse(raw) : [];
      list      = list.filter(a => a.id !== id);
      await env.ENES_USERS.put(key, JSON.stringify(list));
      return json({ ok: true }, 200, origin);
    }

    // ── Admin: Kayıtlı üyeler ────────────────────────────────────────────────
    if (path === '/admin/users' && method === 'GET') {
      if (!await verifyAdminJWT(request, env)) return json({ error: 'Unauthorized' }, 401, origin);
      const emails = new Set();
      // 1) list() — sayfalı (1000+ anahtarda da eksiksiz)
      let cursor;
      do {
        const res = await env.ENES_USERS.list({ prefix: 'user:', cursor });
        res.keys.forEach(k => emails.add(k.name.slice(5))); // 'user:'.length === 5
        cursor = res.list_complete ? null : res.cursor;
      } while (cursor);
      // 2) members:index ile birleştir — list() gecikmesine/eksikliğine karşı
      try {
        const idxRaw = await env.ENES_USERS.get('members:index');
        if (idxRaw) JSON.parse(idxRaw).forEach(e => emails.add(e));
      } catch {}
      // 3) her e-posta için kaydı çek
      const users = (await Promise.all(
        [...emails].map(async em => {
          const raw = await env.ENES_USERS.get(`user:${em}`);
          if (!raw) return null;
          const u = JSON.parse(raw);
          return { email: u.email, name: u.name, phone: u.phone, createdAt: u.createdAt };
        })
      )).filter(Boolean);
      // index'i kendi kendine onar — mevcut tüm üyeleri içersin (yalnız büyür, asla küçülmez)
      try { await env.ENES_USERS.put('members:index', JSON.stringify(users.map(u => u.email))); } catch {}
      users.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return json(users, 200, origin);
    }

    // ── Admin: Kampanya yönetimi ──────────────────────────────────────────────
    if (path === '/admin/campaigns') {
      if (!await verifyAdminJWT(request, env)) return json({ error: 'Unauthorized' }, 401, origin);
      if (method === 'GET') {
        const raw = await env.ENES_USERS.get('campaigns');
        return json(raw ? JSON.parse(raw) : [], 200, origin);
      }
      if (method === 'PUT') {
        const campaigns = await request.json();
        await env.ENES_USERS.put('campaigns', JSON.stringify(campaigns));
        return json({ ok: true }, 200, origin);
      }
    }

    return new Response('Not Found', { status: 404, headers: corsHeaders({}, origin) });
  },
};
