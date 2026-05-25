// Enes Akvaryum — Cloudflare Worker API
// Replaces jsonbin.io as the data backend

const API_KEY = 'Enesakvaryum2024';
const KV_KEY  = 'products';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Api-Key',
};

function corsHeaders(extra = {}) {
  return { ...CORS, ...extra };
}

export default {
  async fetch(request, env) {
    const method = request.method.toUpperCase();

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    // GET — public read
    if (method === 'GET') {
      const raw = await env.ENES_DATA.get(KV_KEY);
      const data = raw ? raw : JSON.stringify({
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
      // Basic validation
      try { JSON.parse(body); } catch {
        return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
          status: 400,
          headers: corsHeaders({ 'Content-Type': 'application/json' }),
        });
      }
      await env.ENES_DATA.put(KV_KEY, body);
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: corsHeaders({ 'Content-Type': 'application/json' }),
      });
    }

    return new Response('Not Found', { status: 404, headers: CORS });
  },
};
