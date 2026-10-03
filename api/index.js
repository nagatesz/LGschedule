const crypto = require('crypto'), fs = require('fs'), path = require('path'), L = require('../lib');
const send = (res, c, o, type) => { res.statusCode = c; res.setHeader('cache-control', 'no-store');
  res.setHeader('content-type', type || 'application/json'); res.end(type ? o : JSON.stringify(o)); };
const sid = req => ((req.headers.cookie || '').match(/(?:^|; )sid=([^;]+)/) || [])[1];
const isAdminEmail = e => (process.env.ADMIN_EMAILS || '').toLowerCase().split(',').map(s => s.trim()).includes(String(e).toLowerCase()), isAdmin = u => isAdminEmail(u.email);
const ts = v => (v ? Date.parse(v) : null), lunchOf = u => u.lunch_on === false ? null : { name: 'Lunch', start: u.lunch_start || '12:13', end: u.lunch_end || '12:43' }, COOKIE = 'HttpOnly; Secure; SameSite=Lax; Path=/';

module.exports = async (req, res) => {
  const url = new URL(req.url, 'http://x'), q = url.searchParams, p = (q.get('p') ?? url.pathname.replace(/^\/api\/?/, '')).replace(/^\/+|\/+$/g, '').split('/'); // vercel.json rewrites every /api/* call here as ?p=<path>
  let who = 'anon';
  try {
    const dom0 = (process.env.ALLOWED_DOMAIN ?? '').trim(), dom = dom0 === '*' ? '' : dom0; // empty or * = any Google account may sign in; set a domain to restrict
    if (p[0] === 'config') return send(res, 200, { clientId: process.env.GOOGLE_CLIENT_ID, domain: dom });

    if (p[0] === 'w') { // Scriptable widget: private per-user token in the URL
      const u = await L.byToken(p[1] || 'x');
      if (!u) { await L.log('unknown', 'error', 'widget call with bad token'); return send(res, 404, { error: 'Bad widget link. Re-copy your script from the dashboard.' }); }
      who = u.label; return send(res, 200, { ...(await L.schedule(u, 'widget')), lunch: lunchOf(u) });
    }

    if (p[0] === 'auth' && p[1] === 'google') {
      const g = await (await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent((req.body || {}).credential || ''))).json();
      if (g.aud !== process.env.GOOGLE_CLIENT_ID || g.email_verified !== 'true' || (dom && !String(g.email).endsWith('@' + dom) && !isAdminEmail(g.email))) {
        await L.log(g.email || 'unknown', 'error', 'login rejected'); return send(res, 403, { error: dom ? `Use your @${dom} Google account.` : 'Google sign-in could not be verified. Try again.' });
      }
      const label = `${g.name} <${g.email.split('@')[0]}>`, seen = new Date().toISOString();
      let u = await L.getUser(g.sub);
      u = u ? await L.patchUser(g.sub, { label, last_seen: seen })
            : (await L.db('POST', 'users', '', { sub: g.sub, email: g.email, name: g.name, label, last_seen: seen, wtoken: crypto.randomBytes(24).toString('hex') }))[0];
      await L.log(label, 'info', 'signed in');
      res.setHeader('set-cookie', `sid=${L.sign({ sub: g.sub, exp: Date.now() + 30 * 864e5 })}; ${COOKIE}; Max-Age=2592000`);
      return send(res, 200, { ok: 1 });
    }
    if (p[0] === 'auth' && p[1] === 'logout') { res.setHeader('set-cookie', 'sid=; Max-Age=0; Path=/'); return send(res, 200, { ok: 1 }); }

    // everything below needs a signed-in user and only ever touches THAT user's row
    const s = L.verify(sid(req)), u = s && await L.getUser(s.sub);
    if (!u) return send(res, 401, { error: 'Not signed in' });
    who = u.label;

    if (p[0] === 'me') return send(res, 200, { name: u.name, email: u.email, hasCookie: !!u.cookie_enc, status: u.status, expires: u.cookie_expires, lastFetch: ts(u.last_fetch), isAdmin: isAdmin(u), override_date: u.override_date || null, lunch_on: u.lunch_on !== false, lunch_start: u.lunch_start || '12:13', lunch_end: u.lunch_end || '12:43' });
    if (p[0] === 'schedule') return send(res, 200, { ...(await L.schedule(u, 'dashboard')), lunch: lunchOf(u) });

    if (p[0] === 'cookie' && req.method === 'POST') {
      const b = req.body || {}, tok = String(b.token || '').trim().replace(/^__Secure-authjs\.session-token=/, '').replace(/;$/, ''), exp = new Date(String(b.expires || '').trim());
      if (tok.length < 20 || !tok.startsWith('eyJ')) return send(res, 400, { error: 'That is not the session token. It should start with eyJ. Make sure you copied the Value of __Secure-authjs.session-token, not the callback-url cookie.' });
      if (isNaN(exp) || exp < Date.now()) return send(res, 400, { error: 'Enter the Expires date exactly as DevTools shows it, e.g. 2026-11-01T18:26:09.739Z (must be in the future).' });
      const t0 = Date.now(); await L.fetchFlex(tok);
      await L.patchUser(u.sub, { cookie_enc: L.enc(tok), cookie_expires: exp.toISOString(), status: 'ok', last_fetch: new Date().toISOString() });
      L.bust(u.sub); await L.log(u.label, 'ok', `token saved and verified, expires ${exp.toISOString()}`, Date.now() - t0); return send(res, 200, { ok: 1, expires: exp.toISOString() });
    }
    if (p[0] === 'settings' && req.method === 'POST') { // the controller drives the widget: it reads these on every refresh
      const b = req.body || {}, patch = {}, tm = /^\d{1,2}:\d{2}$/;
      if ('override_date' in b) { const d = b.override_date; if (d && (!/^\d{4}-\d{2}-\d{2}$/.test(d) || isNaN(Date.parse(d)))) return send(res, 400, { error: 'Pick a valid date.' }); patch.override_date = d || null; }
      if ('lunch_on' in b) { patch.lunch_on = !!b.lunch_on; if (b.lunch_on) { if (!tm.test(b.lunch_start || '') || !tm.test(b.lunch_end || '')) return send(res, 400, { error: 'Enter lunch start and end times.' }); patch.lunch_start = b.lunch_start; patch.lunch_end = b.lunch_end; } }
      const nu = await L.patchUser(u.sub, patch); L.bust(u.sub);
      await L.log(u.label, 'info', 'controller changed widget: ' + JSON.stringify(patch));
      return send(res, 200, { ok: 1, override_date: nu.override_date || null, lunch_on: nu.lunch_on !== false, lunch_start: nu.lunch_start || '12:13', lunch_end: nu.lunch_end || '12:43' });
    }
    if (p[0] === 'token' && req.method === 'POST') {
      await L.patchUser(u.sub, { wtoken: crypto.randomBytes(24).toString('hex') }); await L.log(u.label, 'info', 'widget link reset'); return send(res, 200, { ok: 1 });
    }
    if (p[0] === 'delete' && req.method === 'POST') { // one-click removal of everything we hold
      await L.db('DELETE', 'users', `?sub=eq.${encodeURIComponent(u.sub)}`, null, 'return=minimal'); await L.log(u.label, 'info', 'account deleted by user');
      res.setHeader('set-cookie', 'sid=; Max-Age=0; Path=/'); return send(res, 200, { ok: 1 });
    }
    if (p[0] === 'script') {
      const tpl = fs.readFileSync(path.join(process.cwd(), 'lib', 'widget.template.txt'), 'utf8'), site = `https://${req.headers.host}/`;
      if (!/const API\s*=/.test(tpl)) return send(res, 500, { error: 'Admin: paste your Scriptable script into lib/widget.template.txt' });
      const out = tpl.replace(/const SITE = .*;/, () => `const SITE = "${site}";`).replace(/const API = .*;/, () => `const API = "${site}api/w/${u.wtoken}";`)
        .replace('const LUNCH =', 'let LUNCH =').replace('const json = await req.loadJSON();', () => 'const json = await req.loadJSON();\nif (json.error) throw new Error(json.error);\nif (json.lunch !== undefined) LUNCH = json.lunch;');
      await L.log(u.label, 'info', 'script generated'); return send(res, 200, out, 'text/plain');
    }

    if (p[0] === 'admin') {
      if (!isAdmin(u)) return send(res, 403, { error: 'Admins only' });
      if (p[1] === 'health') {
        const t0 = Date.now(); let dbOk = true, dbErr = null; try { await L.db('GET', 'users', '?select=sub&limit=1'); await L.db('GET', 'logs', '?select=id&limit=1'); } catch (e) { dbOk = false; dbErr = String(e.message).slice(0, 200); }
        const dbMs = Date.now() - t0, t1 = Date.now(); let flex; try { const r = await fetch('https://flex.lkgeorge.org/student/schedule', { redirect: 'manual', signal: AbortSignal.timeout(8000) }); flex = 'reachable (HTTP ' + r.status + ')'; } catch (e) { flex = 'unreachable: ' + e.message; }
        return send(res, 200, { db: dbOk, dbErr, dbMs, flex, flexMs: Date.now() - t1, missingEnv: ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'GOOGLE_CLIENT_ID', 'SESSION_SECRET', 'ENC_KEY', 'ADMIN_EMAILS'].filter(k => !process.env[k]), node: process.version, region: process.env.VERCEL_REGION || null, debugLogs: process.env.DEBUG_LOGS === '1' });
      }
      if (p[1] === 'test' && req.method === 'POST') { // runs a real fetch for that user; returns only counts, never schedule data
        const tu = (await L.db('GET', 'users', '?email=eq.' + encodeURIComponent((req.body || {}).email || '')))[0];
        if (!tu) return send(res, 404, { error: 'No such user' });
        L.bust(tu.sub); await L.log(u.label, 'info', `admin test fetch for ${tu.label}`);
        try { const t = Date.now(), d = await L.schedule(tu, 'admin-test'); return send(res, 200, { ok: 1, blocks: d.all_blocks.length, date: d.date, ms: Date.now() - t }); }
        catch (e) { return send(res, 200, { ok: 0, error: e.message, code: e.code }); }
      }
      if (p[1] === 'users') return send(res, 200, { users: (await L.db('GET', 'users', '?select=name,email,status,cookie_enc,cookie_expires,last_fetch,last_seen&order=created_at.desc'))
        .map(x => ({ name: x.name, email: x.email, status: x.status, hasCookie: !!x.cookie_enc, expires: x.cookie_expires, lastFetch: ts(x.last_fetch), lastSeen: ts(x.last_seen) })) });
      if (p[1] === 'logs') return send(res, 200, { logs: (await L.db('GET', 'logs', `?id=gt.${+q.get('since') || 0}&order=id.desc&limit=300`)).reverse()
        .map(r => ({ id: r.id, t: Date.parse(r.t), user: r.user_label, level: r.level, msg: r.msg, ms: r.ms })) });
    }
    return send(res, 404, { error: 'Not found' });
  } catch (e) {
    if (!e.logged) await L.log(who, 'error', `${req.method} /${p.join('/')}: ${e.message}`);
    send(res, e.code === 'EXPIRED' || e.code === 'NOCOOKIE' ? 409 : 500, { error: e.message, code: e.code });
  }
};
