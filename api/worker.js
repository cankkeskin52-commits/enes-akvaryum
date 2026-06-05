// Enes Akvaryum — Cloudflare Worker API
// Primary: Cloudflare KV  |  Backup: GitHub repo

const API_KEY   = 'Enesakvaryum2024';
const KV_KEY    = 'products';
const GH_REPO   = 'cankkeskin52-commits/enes-akvaryum';
const GH_FILE   = 'backup/data.json';
const GH_BRANCH = 'main';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Api-Key, Authorization',
};

function corsHeaders(extra = {}) { return { ...CORS, ...extra }; }
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders({ 'Content-Type': 'application/json' }),
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

async function jwtKey(env) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(env.JWT_SECRET || 'enes-akvaryum-jwt-secret-2024'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function signJWT(payload, env) {
  const key = await jwtKey(env);
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body   = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig    = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${b64url(sig)}`;
}

async function verifyJWT(token, env) {
  try {
    const [header, body, sig] = token.split('.');
    const key   = await jwtKey(env);
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

    if (method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    // ── Ürünler (eski API — backward compat) ─────────────────────────────────
    if (path === '/' || path === '') {
      if (method === 'GET') {
        const raw  = await env.ENES_DATA.get(KV_KEY);
        const data = raw || JSON.stringify({ fish: [], aquariums: [], reviews: [], plants: [], subscribers: [], visits: 0, plant_products: [], stone_products: [], equipment: [] });
        return new Response(data, { status: 200, headers: corsHeaders({ 'Content-Type': 'application/json' }) });
      }
      if (method === 'PUT') {
        if (request.headers.get('X-Api-Key') !== API_KEY) return json({ error: 'Unauthorized' }, 401);
        const body = await request.text();
        try { JSON.parse(body); } catch { return json({ error: 'Invalid JSON' }, 400); }
        await env.ENES_DATA.put(KV_KEY, body);
        if (env.GITHUB_TOKEN) ctx.waitUntil(backupToGitHub(env.GITHUB_TOKEN, body));
        return json({ ok: true });
      }
    }

    // ── Kayıt ────────────────────────────────────────────────────────────────
    if (path === '/auth/register' && method === 'POST') {
      const { email, password, name, phone } = await request.json();
      if (!email || !password || !name) return json({ error: 'Ad, e-posta ve şifre zorunludur' }, 400);
      const em = email.toLowerCase().trim();
      if (await getUser(env, em)) return json({ error: 'Bu e-posta zaten kayıtlı' }, 409);
      const salt         = crypto.randomUUID();
      const passwordHash = await hashPassword(password, salt);
      const user         = { email: em, name: name.trim(), phone: (phone || '').trim(), passwordHash, salt, createdAt: Date.now() };
      await env.ENES_USERS.put(`user:${em}`, JSON.stringify(user));
      const token = await signJWT({ email: em, exp: Math.floor(Date.now() / 1000) + 86400 * 30 }, env);
      return json({ ok: true, token, user: { email: em, name: user.name, phone: user.phone } });
    }

    // ── Giriş ────────────────────────────────────────────────────────────────
    if (path === '/auth/login' && method === 'POST') {
      const { email, password } = await request.json();
      if (!email || !password) return json({ error: 'E-posta ve şifre zorunludur' }, 400);
      const em   = email.toLowerCase().trim();
      const user = await getUser(env, em);
      if (!user) return json({ error: 'E-posta veya şifre hatalı' }, 401);
      const hash = await hashPassword(password, user.salt);
      if (hash !== user.passwordHash) return json({ error: 'E-posta veya şifre hatalı' }, 401);
      const token = await signJWT({ email: em, exp: Math.floor(Date.now() / 1000) + 86400 * 30 }, env);
      return json({ ok: true, token, user: { email: em, name: user.name, phone: user.phone } });
    }

    // ── Profil ───────────────────────────────────────────────────────────────
    if (path === '/me' && method === 'GET') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401);
      const user = await getUser(env, payload.email);
      if (!user) return json({ error: 'Kullanıcı bulunamadı' }, 404);
      return json({ email: user.email, name: user.name, phone: user.phone, createdAt: user.createdAt });
    }

    // ── Profil güncelle ───────────────────────────────────────────────────────
    if (path === '/me' && method === 'PUT') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401);
      const user = await getUser(env, payload.email);
      if (!user) return json({ error: 'Kullanıcı bulunamadı' }, 404);
      const { name, phone } = await request.json();
      if (name) user.name = name.trim();
      if (phone !== undefined) user.phone = phone.trim();
      await env.ENES_USERS.put(`user:${payload.email}`, JSON.stringify(user));
      return json({ ok: true, user: { email: user.email, name: user.name, phone: user.phone } });
    }

    // ── Şifre değiştir ────────────────────────────────────────────────────────
    if (path === '/me/password' && method === 'PUT') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401);
      const user = await getUser(env, payload.email);
      if (!user) return json({ error: 'Kullanıcı bulunamadı' }, 404);
      const { currentPassword, newPassword } = await request.json();
      if (!currentPassword || !newPassword) return json({ error: 'Mevcut ve yeni şifre zorunludur' }, 400);
      if (newPassword.length < 6) return json({ error: 'Yeni şifre en az 6 karakter olmalıdır' }, 400);
      const checkHash = await hashPassword(currentPassword, user.salt);
      if (checkHash !== user.passwordHash) return json({ error: 'Mevcut şifre hatalı' }, 401);
      const newSalt = crypto.randomUUID();
      user.salt = newSalt;
      user.passwordHash = await hashPassword(newPassword, newSalt);
      await env.ENES_USERS.put(`user:${payload.email}`, JSON.stringify(user));
      return json({ ok: true });
    }

    // ── Favoriler ────────────────────────────────────────────────────────────
    if (path === '/me/favorites') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401);
      const favKey = `favorites:${payload.email}`;
      if (method === 'GET') {
        const raw = await env.ENES_USERS.get(favKey);
        return json(raw ? JSON.parse(raw) : []);
      }
      if (method === 'POST') {
        const { productId } = await request.json();
        if (!productId) return json({ error: 'productId gerekli' }, 400);
        const raw  = await env.ENES_USERS.get(favKey);
        const favs = raw ? JSON.parse(raw) : [];
        const idx  = favs.indexOf(productId);
        if (idx === -1) favs.push(productId); else favs.splice(idx, 1);
        await env.ENES_USERS.put(favKey, JSON.stringify(favs));
        return json({ ok: true, favorites: favs, added: idx === -1 });
      }
    }

    // ── Siparişler ───────────────────────────────────────────────────────────
    if (path === '/me/orders' && method === 'GET') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401);
      const raw = await env.ENES_USERS.get(`orders:${payload.email}`);
      return json(raw ? JSON.parse(raw) : []);
    }

    // ── Kampanyalar (herkese açık) ────────────────────────────────────────────
    if (path === '/campaigns' && method === 'GET') {
      const raw = await env.ENES_USERS.get('campaigns');
      return json(raw ? JSON.parse(raw) : []);
    }

    // ── Admin: Sipariş ekle ──────────────────────────────────────────────────
    if (path === '/admin/orders' && method === 'POST') {
      if (request.headers.get('X-Api-Key') !== API_KEY) return json({ error: 'Unauthorized' }, 401);
      const { email, order } = await request.json();
      if (!email || !order) return json({ error: 'email ve order zorunludur' }, 400);
      const em     = email.toLowerCase().trim();
      const raw    = await env.ENES_USERS.get(`orders:${em}`);
      const orders = raw ? JSON.parse(raw) : [];
      const newOrder = { id: crypto.randomUUID(), ...order, createdAt: Date.now() };
      orders.unshift(newOrder);
      await env.ENES_USERS.put(`orders:${em}`, JSON.stringify(orders));
      return json({ ok: true, order: newOrder });
    }

    // ── Adresler ─────────────────────────────────────────────────────────────
    if (path === '/me/addresses') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401);
      const key = `addresses:${payload.email}`;
      if (method === 'GET') {
        const raw = await env.ENES_USERS.get(key);
        return json(raw ? JSON.parse(raw) : []);
      }
      if (method === 'POST') {
        const { title, name, phone, city, district, fullAddress } = await request.json();
        if (!title || !fullAddress) return json({ error: 'Başlık ve adres zorunludur' }, 400);
        const raw  = await env.ENES_USERS.get(key);
        const list = raw ? JSON.parse(raw) : [];
        const item = { id: crypto.randomUUID(), title, name: name || '', phone: phone || '', city: city || '', district: district || '', fullAddress, createdAt: Date.now() };
        list.push(item);
        await env.ENES_USERS.put(key, JSON.stringify(list));
        return json({ ok: true, address: item });
      }
    }
    if (path.startsWith('/me/addresses/') && method === 'DELETE') {
      const payload = await requireAuth(request, env);
      if (!payload) return json({ error: 'Giriş gerekli' }, 401);
      const id  = path.split('/').pop();
      const key = `addresses:${payload.email}`;
      const raw = await env.ENES_USERS.get(key);
      let list  = raw ? JSON.parse(raw) : [];
      list      = list.filter(a => a.id !== id);
      await env.ENES_USERS.put(key, JSON.stringify(list));
      return json({ ok: true });
    }

    // ── Admin: Kayıtlı üyeler ────────────────────────────────────────────────
    if (path === '/admin/users' && method === 'GET') {
      if (request.headers.get('X-Api-Key') !== API_KEY) return json({ error: 'Unauthorized' }, 401);
      const list = await env.ENES_USERS.list({ prefix: 'user:' });
      const users = await Promise.all(
        list.keys.map(async k => {
          const raw = await env.ENES_USERS.get(k.name);
          if (!raw) return null;
          const u = JSON.parse(raw);
          return { email: u.email, name: u.name, phone: u.phone, createdAt: u.createdAt };
        })
      );
      return json(users.filter(Boolean));
    }

    // ── Admin: Kampanya yönetimi ──────────────────────────────────────────────
    if (path === '/admin/campaigns') {
      if (request.headers.get('X-Api-Key') !== API_KEY) return json({ error: 'Unauthorized' }, 401);
      if (method === 'GET') {
        const raw = await env.ENES_USERS.get('campaigns');
        return json(raw ? JSON.parse(raw) : []);
      }
      if (method === 'PUT') {
        const campaigns = await request.json();
        await env.ENES_USERS.put('campaigns', JSON.stringify(campaigns));
        return json({ ok: true });
      }
    }

    return new Response('Not Found', { status: 404, headers: CORS });
  },
};
