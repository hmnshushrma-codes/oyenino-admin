// ===================================================================
// oyenino-admin — Data owner + Admin dashboard
// 
// Two jobs:
// 1. Internal API (/api/ingest) — called by oyenino-forms via service binding
// 2. Admin dashboard (/admin/*) — login form + cookie session + D1 reads
//
// Auth: ADMIN_KEY entered in login form → HMAC-signed HttpOnly cookie
// Key NEVER appears in URL, logs, or browser history
// ===================================================================

const COOKIE_NAME = 'oye_sess';
const SESSION_MAX_AGE = 7 * 24 * 60 * 60; // 7 days

// ===================================================================
// D1 OPERATIONS
// ===================================================================

async function insertSubmission(db, data, meta) {
  return db.prepare(`
    INSERT INTO submissions
      (form_name, name, email, phone, city, service, message, source, device, location, ip, referer, raw_data)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    data._form_name || 'unknown',
    data.name || null,
    data.email || null,
    data.phone_formatted || data.phone || null,
    data.city || null,
    data.service || null,
    data.message || null,
    data.source || null,
    data.device ? JSON.stringify(data.device) : null,
    data.location ? JSON.stringify(data.location) : null,
    meta.ip || null,
    meta.referer || null,
    JSON.stringify(data)
  ).run();
}

// ===================================================================
// SESSION AUTH — HMAC-signed HttpOnly cookie
// ===================================================================

async function signSession(payload, secret) {
  const raw = JSON.stringify(payload);
  const encoded = btoa(raw).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(encoded));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${encoded}.${sigB64}`;
}

async function verifySession(cookie, secret) {
  try {
    const [encoded, sigB64] = cookie.split('.');
    if (!encoded || !sigB64) return null;
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBuf = Uint8Array.from(
      atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')),
      c => c.charCodeAt(0)
    );
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(encoded));
    if (!valid) return null;
    const payload = JSON.parse(atob(encoded.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function getCookie(request, name) {
  const cookies = request.headers.get('Cookie') || '';
  const match = cookies.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}

// ===================================================================
// HTML PAGES
// ===================================================================

function loginPageHTML(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oye Nino — Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#111;border:1px solid #222;border-radius:16px;padding:48px;max-width:380px;width:90%}
h1{font-size:24px;margin-bottom:6px;text-align:center} h1 span{color:#f97316}
.sub{text-align:center;color:#555;font-size:13px;margin-bottom:32px}
label{display:block;font-size:12px;color:#666;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
input[type=password]{width:100%;padding:14px 16px;background:#0a0a0a;border:1px solid #333;border-radius:10px;color:#fff;font-size:15px;outline:none;transition:border .2s}
input[type=password]:focus{border-color:#f97316}
button{width:100%;margin-top:20px;padding:14px;background:#f97316;color:#000;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;transition:all .2s}
button:hover{background:#fb923c;transform:translateY(-1px)}
.error{background:#2a1010;border:1px solid #5a2020;color:#f87171;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:20px;text-align:center}
.note{text-align:center;margin-top:20px;font-size:11px;color:#333}
</style>
</head>
<body>
<div class="card">
  <h1><span>oye</span>nino</h1>
  <p class="sub">admin access</p>
  ${error ? `<div class="error">${error}</div>` : ''}
  <form method="POST" action="/admin/login">
    <label>Admin Key</label>
    <input type="password" name="admin_key" placeholder="Enter your admin key" autofocus required>
    <button type="submit">Login</button>
  </form>
  <p class="note">Restricted access — unauthorized attempts are logged</p>
</div>
</body>
</html>`;
}

function dashboardHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oye Nino — Leads</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh}
.topbar{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;background:#111;border-bottom:1px solid #222}
.topbar h1{font-size:18px;color:#fff} .topbar h1 span{color:#f97316}
.topbar .right{display:flex;align-items:center;gap:16px}
.topbar .meta{font-size:12px;color:#555}
.topbar a{color:#666;text-decoration:none;font-size:12px;padding:6px 14px;border:1px solid #333;border-radius:8px;transition:all .2s}
.topbar a:hover{border-color:#f97316;color:#f97316}
.stats{display:flex;gap:12px;padding:16px 24px;flex-wrap:wrap}
.stat-card{background:#151515;border:1px solid #222;border-radius:10px;padding:14px 20px;min-width:110px}
.stat-card .num{font-size:28px;font-weight:700;color:#fff}
.stat-card .label{font-size:12px;color:#666;margin-top:2px}
.filters{display:flex;gap:8px;padding:0 24px 16px;flex-wrap:wrap}
.filters button{padding:8px 16px;border-radius:20px;border:1px solid #333;background:#181818;color:#ccc;cursor:pointer;font-size:13px;transition:all .2s}
.filters button.active{background:#f97316;color:#000;border-color:#f97316;font-weight:600}
.filters button:hover{border-color:#f97316}
.table-wrap{padding:0 24px 24px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;color:#666;font-weight:500;border-bottom:1px solid #222;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
td{padding:12px;border-bottom:1px solid #1a1a1a;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:#151515}
.badge{padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;display:inline-block}
.badge-new{background:#1a3a1a;color:#4ade80}
.badge-contacted{background:#1a2a3a;color:#60a5fa}
.badge-archived{background:#2a2a2a;color:#888}
.badge-form{background:#2a1a0a;color:#f97316}
.actions button{padding:4px 10px;border-radius:6px;border:1px solid #333;background:#1a1a1a;color:#ccc;cursor:pointer;font-size:11px;margin-right:4px}
.actions button:hover{border-color:#f97316;color:#f97316}
.empty{text-align:center;padding:60px;color:#444}
.msg-preview{cursor:pointer;text-decoration:underline dotted #555}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.modal-bg.open{display:flex}
.modal{background:#151515;border:1px solid #333;border-radius:12px;padding:24px;max-width:520px;width:90%;max-height:80vh;overflow-y:auto}
.modal h3{margin-bottom:16px;color:#f97316;font-size:16px}
.modal .field{margin-bottom:8px;font-size:13px;line-height:1.5}
.modal .field .k{color:#666;display:inline-block;min-width:80px}
.modal .field .v{color:#ddd}
.modal .msg-box{background:#0a0a0a;border:1px solid #222;border-radius:8px;padding:14px;margin:12px 0;font-size:13px;line-height:1.6;white-space:pre-wrap;word-break:break-word;color:#bbb}
.modal .section{color:#555;font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin:16px 0 8px;padding-top:12px;border-top:1px solid #222}
.modal pre{font-size:11px;color:#888;line-height:1.5;white-space:pre-wrap;word-break:break-word}
.modal .close-btn{margin-top:16px;padding:8px 20px;background:#f97316;color:#000;border:none;border-radius:8px;cursor:pointer;font-weight:600}
@media(max-width:768px){
  .topbar,.filters,.table-wrap,.stats{padding-left:12px;padding-right:12px}
  td{font-size:12px;padding:8px 6px}
}
</style>
</head>
<body>
<div class="topbar">
  <h1><span>oye</span>nino — leads</h1>
  <div class="right">
    <span class="meta" id="meta"></span>
    <a href="/admin/logout">Logout</a>
  </div>
</div>
<div class="stats" id="stats"></div>
<div class="filters" id="filters">
  <button class="active" data-form="">All</button>
  <button data-form="contact">💼 Consulting</button>
  <button data-form="prompts_gate">🔓 Prompts</button>
  <button data-form="shopping_prompt_gate">🛒 Shopping</button>
  <button data-form="existence_series">🎨 Existence</button>
</div>
<div class="table-wrap">
  <table>
    <thead><tr>
      <th>Status</th><th>Form</th><th>Name</th><th>Email</th><th>Phone</th>
      <th>Service</th><th>Message</th><th>City</th><th>Date</th><th>Actions</th>
    </tr></thead>
    <tbody id="tbody"><tr><td colspan="10" class="empty">Loading...</td></tr></tbody>
  </table>
</div>

<div class="modal-bg" id="modal" onclick="if(event.target===this)this.classList.remove('open')">
  <div class="modal" id="modal-content"></div>
</div>

<script>
var currentForm = '';

function api(path, opts) {
  return fetch(path, opts).then(function(r) {
    if (r.status === 401) { location.href = '/admin'; return null; }
    return r.json();
  });
}

function loadStats() {
  api('/admin/api/stats').then(function(data) {
    if (!data) return;
    var el = document.getElementById('stats');
    var t = {};
    data.forEach(function(r) { t[r.status] = (t[r.status]||0) + r.count; });
    var total = Object.values(t).reduce(function(a,b){return a+b}, 0);
    var cards = [
      {num:total,label:'Total'},
      {num:t.new||0,label:'New'},
      {num:t.contacted||0,label:'Contacted'},
      {num:t.archived||0,label:'Archived'}
    ];
    el.innerHTML = cards.map(function(s) {
      return '<div class="stat-card"><div class="num">'+s.num+'</div><div class="label">'+s.label+'</div></div>';
    }).join('');
    document.getElementById('meta').textContent = total + ' leads';
  });
}

function loadRows(form) {
  var tbody = document.getElementById('tbody');
  tbody.innerHTML = '<tr><td colspan="10" class="empty">Loading...</td></tr>';
  var url = '/admin/api/submissions?limit=200';
  if (form) url += '&form=' + form;
  api(url).then(function(data) {
    if (!data) return;
    var rows = data.results || [];
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="10" class="empty">No submissions yet</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(function(r) {
      var d = r.created_at
        ? new Date(r.created_at+'Z').toLocaleString('en-IN',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'})
        : '\u2014';
      var bc = r.status==='new' ? 'badge-new' : r.status==='contacted' ? 'badge-contacted' : 'badge-archived';
      var msg = r.message ? (r.message.length > 35 ? r.message.slice(0,35)+'\u2026' : r.message) : '\u2014';
      return '<tr>'+
        '<td><span class="badge '+bc+'">'+(r.status||'new')+'</span></td>'+
        '<td><span class="badge badge-form">'+(r.form_name||'\u2014')+'</span></td>'+
        '<td>'+(r.name||'\u2014')+'</td>'+
        '<td>'+(r.email||'\u2014')+'</td>'+
        '<td>'+(r.phone||'\u2014')+'</td>'+
        '<td>'+(r.service||'\u2014')+'</td>'+
        '<td class="msg-preview" onclick="showDetail('+r.id+')">'+msg+'</td>'+
        '<td>'+(r.city||'\u2014')+'</td>'+
        '<td>'+d+'</td>'+
        '<td class="actions">'+
          (r.status!=='contacted' ? '<button onclick="event.stopPropagation();setStatus('+r.id+',\'contacted\')">\u2713</button>' : '')+
          (r.status!=='archived' ? '<button onclick="event.stopPropagation();setStatus('+r.id+',\'archived\')">\u2717</button>' : '')+
        '</td></tr>';
    }).join('');
  });
}

function setStatus(id, status) {
  api('/admin/api/submissions/'+id, {
    method:'PATCH',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({status:status})
  }).then(function() {
    loadRows(currentForm);
    loadStats();
  });
}

function showDetail(id) {
  api('/admin/api/submissions/'+id).then(function(d) {
    if (!d) return;
    var mc = document.getElementById('modal-content');
    var h = '<h3>'+(d.name||'Unknown')+' \u2014 '+(d.form_name||'')+'</h3>';
    var fields = [
      ['Name', d.name], ['Email', d.email], ['Phone', d.phone],
      ['City', d.city], ['Service', d.service], ['Source', d.source],
      ['Status', d.status || 'new'], ['Date', d.created_at]
    ];
    fields.forEach(function(f) {
      if (f[1]) h += '<div class="field"><span class="k">'+f[0]+'</span> <span class="v">'+f[1]+'</span></div>';
    });
    if (d.message) {
      h += '<div class="msg-box">'+d.message.replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</div>';
    }
    if (d.device) {
      h += '<div class="section">Device</div>';
      try { h += '<pre>'+JSON.stringify(JSON.parse(d.device),null,2)+'</pre>'; }
      catch(e) { h += '<pre>'+d.device+'</pre>'; }
    }
    if (d.location) {
      h += '<div class="section">Location</div>';
      try { h += '<pre>'+JSON.stringify(JSON.parse(d.location),null,2)+'</pre>'; }
      catch(e) { h += '<pre>'+d.location+'</pre>'; }
    }
    h += '<div class="section">Meta</div>';
    h += '<pre>IP: '+(d.ip||'\u2014')+'\nReferer: '+(d.referer||'\u2014')+'</pre>';
    h += '<button class="close-btn" onclick="document.getElementById(\'modal\').classList.remove(\'open\')">Close</button>';
    mc.innerHTML = h;
    document.getElementById('modal').classList.add('open');
  });
}

document.getElementById('filters').addEventListener('click', function(e) {
  if (e.target.tagName!=='BUTTON') return;
  document.querySelectorAll('.filters button').forEach(function(b){b.classList.remove('active')});
  e.target.classList.add('active');
  currentForm = e.target.dataset.form;
  loadRows(currentForm);
});

loadStats();
loadRows('');
</script>
</body>
</html>`;
}

// ===================================================================
// MAIN HANDLER
// ===================================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ══════════════════════════════════════════
    // INTERNAL INGEST — called by oyenino-forms via service binding
    // Not publicly accessible (service bindings are internal only)
    // ══════════════════════════════════════════

    if (url.pathname === '/api/ingest' && request.method === 'POST') {
      try {
        const { data, meta } = await request.json();
        await insertSubmission(env.DB, data, meta);
        return new Response(JSON.stringify({ ok: true }), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err) {
        console.log("Ingest error:", err.message);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500, headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    // ══════════════════════════════════════════
    // ADMIN ROUTES — /admin/*
    // ══════════════════════════════════════════

    if (url.pathname.startsWith('/admin')) {

      // ── Login page ──
      if ((url.pathname === '/admin' || url.pathname === '/admin/' || url.pathname === '/admin/login') && request.method === 'GET') {
        const cookie = getCookie(request, COOKIE_NAME);
        if (cookie) {
          const session = await verifySession(cookie, env.ADMIN_KEY);
          if (session) return Response.redirect(`${url.origin}/admin/dashboard`, 302);
        }
        return new Response(loginPageHTML(null), {
          headers: { 'Content-Type': 'text/html;charset=UTF-8' },
        });
      }

      // ── Login submit ──
      if (url.pathname === '/admin/login' && request.method === 'POST') {
        const fd = await request.formData();
        const submitted = fd.get('admin_key') || '';

        // Constant-time comparison
        const a = new TextEncoder().encode(submitted);
        const b = new TextEncoder().encode(env.ADMIN_KEY);
        let match = a.length === b.length;
        const len = Math.max(a.length, b.length);
        for (let i = 0; i < len; i++) {
          if ((a[i] || 0) !== (b[i] || 0)) match = false;
        }

        if (!match) {
          const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
          console.log(`[AUTH FAIL] IP: ${ip} at ${new Date().toISOString()}`);
          return new Response(loginPageHTML('Invalid admin key'), {
            status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' },
          });
        }

        const token = await signSession(
          { role: 'admin', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE },
          env.ADMIN_KEY
        );

        return new Response(null, {
          status: 302,
          headers: {
            Location: '/admin/dashboard',
            'Set-Cookie': `${COOKIE_NAME}=${token}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_MAX_AGE}`,
          },
        });
      }

      // ── Logout ──
      if (url.pathname === '/admin/logout') {
        return new Response(null, {
          status: 302,
          headers: {
            Location: '/admin',
            'Set-Cookie': `${COOKIE_NAME}=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
          },
        });
      }

      // ── Session check for all other admin routes ──
      const cookie = getCookie(request, COOKIE_NAME);
      const session = cookie ? await verifySession(cookie, env.ADMIN_KEY) : null;

      if (!session) {
        if (url.pathname.startsWith('/admin/api/')) {
          return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401, headers: { 'Content-Type': 'application/json' },
          });
        }
        return Response.redirect(`${url.origin}/admin`, 302);
      }

      // ── Dashboard ──
      if (url.pathname === '/admin/dashboard' && request.method === 'GET') {
        return new Response(dashboardHTML(), {
          headers: { 'Content-Type': 'text/html;charset=UTF-8' },
        });
      }

      // ── API: List submissions ──
      if (url.pathname === '/admin/api/submissions' && request.method === 'GET') {
        const form = url.searchParams.get('form');
        const status = url.searchParams.get('status');
        const limit = parseInt(url.searchParams.get('limit') || '50');
        let query = 'SELECT * FROM submissions WHERE 1=1';
        const params = [];
        if (form) { query += ' AND form_name = ?'; params.push(form); }
        if (status) { query += ' AND status = ?'; params.push(status); }
        query += ' ORDER BY created_at DESC LIMIT ?';
        params.push(limit);
        const results = await env.DB.prepare(query).bind(...params).all();
        return new Response(JSON.stringify({ results: results.results }), {
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // ── API: Single submission ──
      if (url.pathname.match(/^\/admin\/api\/submissions\/\d+$/) && request.method === 'GET') {
        const id = url.pathname.split('/').pop();
        const row = await env.DB.prepare('SELECT * FROM submissions WHERE id = ?').bind(id).first();
        if (!row) return new Response('Not found', { status: 404 });
        return new Response(JSON.stringify(row), {
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // ── API: Update status/notes ──
      if (url.pathname.match(/^\/admin\/api\/submissions\/\d+$/) && request.method === 'PATCH') {
        const id = url.pathname.split('/').pop();
        const body = await request.json();
        const updates = [];
        const vals = [];
        if (body.status) { updates.push('status = ?'); vals.push(body.status); }
        if (body.notes !== undefined) { updates.push('notes = ?'); vals.push(body.notes); }
        if (updates.length) {
          vals.push(id);
          await env.DB.prepare(`UPDATE submissions SET ${updates.join(', ')} WHERE id = ?`).bind(...vals).run();
        }
        return new Response(JSON.stringify({ ok: true }), {
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // ── API: Stats ──
      if (url.pathname === '/admin/api/stats' && request.method === 'GET') {
        const stats = await env.DB.prepare(`
          SELECT form_name, status, COUNT(*) as count
          FROM submissions GROUP BY form_name, status
        `).all();
        return new Response(JSON.stringify(stats.results), {
          headers: { 'Content-Type': 'application/json' },
        });
      }

      return new Response('Not found', { status: 404 });
    }

    return new Response('Not found', { status: 404 });
  },
};