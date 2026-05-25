// Enes Akvaryum — Cloudflare Worker API
// Primary: Cloudflare KV  |  Backup: GitHub repo

const API_KEY    = 'Enesakvaryum2024';
const KV_KEY     = 'products';
const GH_REPO    = 'cankkeskin52-commits/enes-akvaryum';
const GH_FILE    = 'backup/data.json';
const GH_BRANCH  = 'main';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Api-Key',
};

function corsHeaders(extra = {}) {
  return { ...CORS, ...extra };
}

// GitHub'a veriyi yedekle (arka planda, hata sessizce geçer)
async function backupToGitHub(token, body) {
  try {
    const apiBase = `https://api.github.com/repos/${GH_REPO}/contents/${GH_FILE}`;
    const headers = {
      'Authorization': `token ${token}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
      'User-Agent': 'enes-akvaryum-worker',
    };

    // Mevcut SHA'yı al (dosya varsa güncelle, yoksa oluştur)
    let sha = null;
    const getResp = await fetch(apiBase + `?ref=${GH_BRANCH}`, { headers });
    if (getResp.ok) {
      const current = await getResp.json();
      sha = current.sha;
    }

    const now = new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' });
    const content = btoa(unescape(encodeURIComponent(body)));
    const payload = {
      message: `🐠 Otomatik yedek — ${now}`,
      content,
      branch: GH_BRANCH,
      ...(sha ? { sha } : {}),
    };

    await fetch(apiBase, {
      method: 'PUT',
      headers,
      body: JSON.stringify(payload),
    });
  } catch (e) {
    // Yedek başarısız olsa bile ana işlem etkilenmiyor
    console.error('GitHub backup failed:', e.message);
  }
}

export default {
  async fetch(request, env, ctx) {
    const method = request.method.toUpperCase();

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    // GET — public read
    if (method === 'GET') {
      const raw = await env.ENES_DATA.get(KV_KEY);
      const data = raw || JSON.stringify({
        fish: [], aquariums: [], reviews: [], plants: [], subscribers: [], visits: 0
      });
      return new Response(data, {
        status: 200,
        headers: corsHeaders({ 'Content-Type': 'application/json' }),
      });
    }

    // PUT — authenticated write
    if (method === 'PUT') {
      const key = request.headers.get('X-Api-Key');
      if (key !== API_KEY) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: corsHeaders({ 'Content-Type': 'application/json' }),
        });
      }

      const body = await request.text();
      try { JSON.parse(body); } catch {
        return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
          status: 400,
          headers: corsHeaders({ 'Content-Type': 'application/json' }),
        });
      }

      // 1. KV'ye kaydet (primary)
      await env.ENES_DATA.put(KV_KEY, body);

      // 2. GitHub'a yedekle (background, hata ana işlemi etkilemez)
      if (env.GITHUB_TOKEN) {
        ctx.waitUntil(backupToGitHub(env.GITHUB_TOKEN, body));
      }

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: corsHeaders({ 'Content-Type': 'application/json' }),
      });
    }

    return new Response('Not Found', { status: 404, headers: CORS });
  },
};
