const crypto = require('crypto'), E = process.env;

// --- Supabase (PostgREST over fetch). Uses the SERVICE key, which only ever lives in Vercel env vars.
const SK = E.SUPABASE_SERVICE_KEY || '', BASE = (E.SUPABASE_URL || '').trim().replace(/\/+$/, '');
const H = { apikey: SK, 'content-type': 'application/json' }; if (SK.startsWith('eyJ')) H.Authorization = 'Bearer ' + SK; // new sb_secret_ keys go in apikey only
async function db(method, tbl, qs = '', body, prefer = 'return=representation') {
  const r = await fetch(`${BASE}/rest/v1/${tbl}${qs}`, { method, headers: { ...H, Prefer: prefer }, body: body && JSON.stringify(body) });
  const t = await r.text(); if (!r.ok) throw new Error('database: ' + t); return t ? JSON.parse(t) : null;
}
const eq = encodeURIComponent;
const getUser = async sub => (await db('GET', 'users', `?sub=eq.${eq(sub)}`))[0] || null;
const byToken = async t => (await db('GET', 'users', `?wtoken=eq.${eq(t)}`))[0] || null;
const patchUser = async (sub, p) => (await db('PATCH', 'users', `?sub=eq.${eq(sub)}`, p))[0];

// --- Flex session tokens are encrypted at rest (AES-256-GCM); login sessions are HMAC-signed
const KEY = crypto.createHash('sha256').update(E.ENC_KEY || '').digest();
const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([c.update(t, 'utf8'), c.final()]); return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64'); };
const dec = s => { const b = Buffer.from(s, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', KEY, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'); };
const mac = b => crypto.createHmac('sha256', E.SESSION_SECRET).update(b).digest('base64url');
const sign = p => { const b = Buffer.from(JSON.stringify(p)).toString('base64url'); return b + '.' + mac(b); };
const verify = t => { try { return verify0(t); } catch { return null; } };
const verify0 = t => { const [b, s] = (t || '').split('.'); if (!s) return null; const ok = mac(b);
  if (s.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(ok))) return null;
  const p = JSON.parse(Buffer.from(b, 'base64url')); return p.exp > Date.now() ? p : null; };

// --- live debug log: every line is tagged with the user it belongs to
const log = async (user, level, msg, ms) => {
  console.log(`[${level}] ${user}: ${msg}` + (ms != null ? ` (${ms}ms)` : ''));
  try { await db('POST', 'logs', '', { user_label: user, level, msg, ms }, 'return=minimal'); } catch {}
};

// debug lines go to the database only when DEBUG_LOGS=1 (otherwise Vercel console only)
const debug = (user, msg) => E.DEBUG_LOGS === '1' ? log(user, 'debug', msg) : console.log(`[debug] ${user}: ${msg}`);
// --- Flex: ported from the original Python API. The schedule is embedded in the page's Next.js flight data.
const FLEX = 'https://flex.lkgeorge.org/student/schedule';
const expired = () => Object.assign(new Error('Flex rejected your token. Import a fresh one in your dashboard.'), { code: 'EXPIRED' });
function nyNow() { // Vercel runs in UTC, so school time must be computed explicitly
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-CA', { timeZone: 'America/New_York', hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).formatToParts(new Date()).map(x => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, mins: +p.hour * 60 + +p.minute };
}
function extractObj(str) { // string-aware brace matching starting at "initialDay":
  const i = str.indexOf('"initialDay":'); if (i < 0) return null;
  const st = str.indexOf('{', i); if (st < 0) return null;
  let depth = 0, inStr = false, esc = false;
  for (let k = st; k < str.length; k++) {
    const c = str[k];
    if (inStr) { if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true; else if (c === '{') depth++; else if (c === '}' && --depth === 0) return JSON.parse(str.slice(st, k + 1));
  }
  return null;
}
function parseFlex(html) {
  const re = /self\.__next_f\.push\(\[\d+,"((?:[^"\\]|\\.)*)"\]\)/g; let m;
  while ((m = re.exec(html))) {
    if (!m[1].includes('initialDay')) continue;
    try {
      const str = JSON.parse('"' + m[1] + '"'), data = extractObj(str), sd = str.match(/"schoolDays":\[(.*?)\]/);
      if (data) return { data, days: sd ? JSON.parse('[' + sd[1] + ']') : [] };
    } catch {}
  }
  throw Object.assign(new Error("Flex's page didn't contain a schedule. If your token is fresh, Flex may have changed its format."), { code: 'PARSE' });
}
async function flexGet(url, headers) { // 8s timeout, one retry on network error or 5xx
  for (let i = 0; ; i++) {
    try { const r = await fetch(url, { headers, redirect: 'manual', signal: AbortSignal.timeout(8000) }); if (r.status >= 500 && i < 1) continue; return r; }
    catch (e) { if (i < 1) continue; throw new Error('Could not reach Flex (' + (e.name === 'TimeoutError' ? 'timed out after 8s' : e.message) + ')'); }
  }
}
async function flexPage(token, date) {
  const r = await flexGet(FLEX + (date ? '?date=' + date : ''), { cookie: '__Secure-authjs.session-token=' + token, 'user-agent': 'Mozilla/5.0' });
  if ((r.status >= 300 && r.status < 400) || r.status === 401 || r.status === 403) throw expired();
  if (!r.ok) throw new Error('Flex returned HTTP ' + r.status);
  const html = await r.text();
  try { return parseFlex(html); } catch (e) { e.message += ` (HTTP ${r.status}, ${html.length} bytes)`; throw e; }
}
async function fetchFlex(token, date) {
  if (date) { const { data } = await flexPage(token, date); return { date: data.date, letter_day: data.letter, all_blocks: data.blocks || [], showing_future_day: true, is_override: true }; }
  const now = nyNow();
  let { data, days } = await flexPage(token);
  const last = (data.blocks || []).slice(-1)[0], [h, mi] = last ? String(last.end).split(':').map(Number) : [0, 0];
  const after = last && now.mins > (h < 6 ? h + 12 : h) * 60 + mi;
  if (!days.includes(now.date) || after) { // school is out: show the next school day, like the original API
    const next = days.find(d => d > now.date);
    if (next) { try { data = (await flexPage(token, next)).data; } catch {} }
  }
  return { date: data.date, letter_day: data.letter, all_blocks: data.blocks || [], showing_future_day: data.date !== now.date };
}

// --- per-user schedule: expiry check first, then a 30s in-memory cache (never written to the database)
const memo = new Map(), bust = sub => { for (const k of memo.keys()) if (k.startsWith(sub + '|')) memo.delete(k); };
async function schedule(u, src) {
  const t0 = Date.now(), fail = (code, m) => Object.assign(new Error(m), { code, logged: true });
  if (!u.cookie_enc) throw fail('NOCOOKIE', 'No Flex token saved yet. Open your dashboard.');
  if (u.cookie_expires && Date.parse(u.cookie_expires) < Date.now()) {
    if (u.status !== 'expired') { await patchUser(u.sub, { status: 'expired' }); await log(u.label, 'error', `${src} -> token expired at ${u.cookie_expires}`); }
    throw fail('EXPIRED', 'Your Flex token has expired. Import a new one in your dashboard.');
  }
  const key = u.sub + '|' + (u.override_date || ''), hit = memo.get(key);
  if (hit && Date.now() - hit.at < 30000) { debug(u.label, `${src} -> cache hit (${Math.round((Date.now() - hit.at) / 1000)}s old)`); return hit.d; }
  try {
    const d = await fetchFlex(dec(u.cookie_enc), u.override_date), now = new Date().toISOString();
    memo.set(key, { d, at: Date.now() });
    await patchUser(u.sub, { last_fetch: now, status: 'ok' });
    await log(u.label, 'ok', `${src} -> Flex returned ${d.all_blocks.length} blocks for ${d.date}`, Date.now() - t0);
    if (Math.random() < 0.02) db('DELETE', 'logs', '?t=lt.' + encodeURIComponent(new Date(Date.now() - 864e5).toISOString()), null, 'return=minimal').catch(() => {}); // keep 24h of logs
    return d;
  } catch (e) {
    const stale = memo.get(key); // Flex hiccup: serve a copy up to 10 min old instead of breaking the widget
    if (e.code !== 'EXPIRED' && stale && Date.now() - stale.at < 600000) {
      await log(u.label, 'warn', `${src} -> Flex failed (${e.message}); served stale copy ${Math.round((Date.now() - stale.at) / 1000)}s old`, Date.now() - t0); return stale.d;
    }
    await patchUser(u.sub, { status: e.code === 'EXPIRED' ? 'expired' : 'error' });
    await log(u.label, 'error', `${src} -> ${e.message}`, Date.now() - t0); e.logged = true; throw e;
  }
}
module.exports = { db, getUser, byToken, patchUser, enc, dec, sign, verify, log, debug, fetchFlex, schedule, bust };
