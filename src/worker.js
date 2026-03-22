// ===================================================================
// oyenino-admin — Data owner + Admin dashboard
//
// Login flow: Email → OTP (via Resend) → Admin Key → Session cookie
// Only hmnshu26@gmail.com can login
// ===================================================================

const COOKIE_NAME = 'oye_sess';
const SESSION_MAX_AGE = 7 * 24 * 60 * 60;
const ADMIN_EMAIL = 'hmnshu26@gmail.com';
const OTP_EXPIRY = 5 * 60; // 5 minutes

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
// OTP HELPERS
// ===================================================================

function generateOTP() {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return String(100000 + (arr[0] % 900000));
}

async function sendOTPEmail(env, otp) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.EMAIL_FROM || 'onboarding@resend.dev',
      to: ADMIN_EMAIL,
      subject: '🔐 Oye Nino Admin — Login OTP',
      text: `Your OTP is: ${otp}\n\nValid for 5 minutes. If you didn't request this, ignore it.`,
    }),
  });
  return res.ok;
}

// ===================================================================
// HTML PAGES
// ===================================================================

const PAGE_STYLE = `
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#111;border:1px solid #222;border-radius:16px;padding:48px;max-width:400px;width:90%}
h1{font-size:24px;margin-bottom:6px;text-align:center} h1 span{color:#f97316}
.sub{text-align:center;color:#555;font-size:13px;margin-bottom:32px}
label{display:block;font-size:12px;color:#666;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
input{width:100%;padding:14px 16px;background:#0a0a0a;border:1px solid #333;border-radius:10px;color:#fff;font-size:15px;outline:none;transition:border .2s;margin-bottom:16px}
input:focus{border-color:#f97316}
button{width:100%;margin-top:4px;padding:14px;background:#f97316;color:#000;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;transition:all .2s}
button:hover{background:#fb923c;transform:translateY(-1px)}
.error{background:#2a1010;border:1px solid #5a2020;color:#f87171;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:20px;text-align:center}
.success{background:#0a2a1a;border:1px solid #1a5a2a;color:#4ade80;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:20px;text-align:center}
.note{text-align:center;margin-top:20px;font-size:11px;color:#333}
`;

function emailPageHTML(error) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Oye Nino — Admin</title><style>${PAGE_STYLE}</style></head>
<body><div class="card">
  <h1><span>oye</span>nino</h1>
  <p class="sub">admin access</p>
  ${error ? `<div class="error">${error}</div>` : ''}
  <form method="POST" action="/admin/send-otp">
    <label>Email</label>
    <input type="email" name="email" placeholder="Enter your email" autofocus required>
    <button type="submit">Send OTP</button>
  </form>
  <p class="note">Restricted access — unauthorized attempts are logged</p>
</div></body></html>`;
}

function otpPageHTML(error, success) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Oye Nino — Verify</title><style>${PAGE_STYLE}</style></head>
<body><div class="card">
  <h1><span>oye</span>nino</h1>
  <p class="sub">verify your identity</p>
  ${error ? `<div class="error">${error}</div>` : ''}
  ${success ? `<div class="success">${success}</div>` : ''}
  <form method="POST" action="/admin/login">
    <label>OTP (check your email)</label>
    <input type="text" name="otp" placeholder="6-digit code" inputmode="numeric" maxlength="6" autofocus required>
    <label>Admin Key</label>
    <input type="password" name="admin_key" placeholder="Enter your admin key" required>
    <button type="submit">Login</button>
  </form>
  <p class="note">OTP valid for 5 minutes</p>
</div></body></html>`;
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
  }).catch(function() { return null; });
}
function loadStats() {
  api('/admin/api/stats').then(function(data) {
    if (!data || !Array.isArray(data)) return;
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
  }).then(function() { loadRows(currentForm); loadStats(); });
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
    if (d.message) h += '<div class="msg-box">'+d.message.replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</div>';
    if (d.device) {
      h += '<div class="section">Device</div>';
      try { h += '<pre>'+JSON.stringify(JSON.parse(d.device),null,2)+'</pre>'; } catch(e) { h += '<pre>'+d.device+'</pre>'; }
    }
    if (d.location) {
      h += '<div class="section">Location</div>';
      try { h += '<pre>'+JSON.stringify(JSON.parse(d.location),null,2)+'</pre>'; } catch(e) { h += '<pre>'+d.location+'</pre>'; }
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
    // INTERNAL INGEST — service binding only
    // ══════════════════════════════════════════

    if (url.pathname === '/api/ingest' && request.method === 'POST') {
      try {
        const { data, meta } = await request.json();
        await insertSubmission(env.DB, data, meta);
        return Response.json({ ok: true });
      } catch (err) {
        console.log("Ingest error:", err.message);
        return Response.json({ error: err.message }, { status: 500 });
      }
    }

    // ══════════════════════════════════════════
    // ADMIN ROUTES
    // ══════════════════════════════════════════

    if (url.pathname.startsWith('/admin')) {

      // ── Step 1: Email page (GET /admin) ──
      if ((url.pathname === '/admin' || url.pathname === '/admin/' || url.pathname === '/admin/login') && request.method === 'GET') {
        // Already logged in?
        const cookie = getCookie(request, COOKIE_NAME);
        if (cookie) {
          const session = await verifySession(cookie, env.ADMIN_KEY);
          if (session) return Response.redirect(`${url.origin}/admin/dashboard`, 302);
        }
        return new Response(emailPageHTML(null), {
          headers: { 'Content-Type': 'text/html;charset=UTF-8' },
        });
      }

      // ── Step 2: Send OTP (POST /admin/send-otp) ──
      if (url.pathname === '/admin/send-otp' && request.method === 'POST') {
        const fd = await request.formData();
        const email = (fd.get('email') || '').trim().toLowerCase();

        if (email !== ADMIN_EMAIL) {
          const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
          console.log(`[AUTH FAIL] Wrong email: ${email}, IP: ${ip}`);
          return new Response(emailPageHTML('Access denied'), {
            status: 403, headers: { 'Content-Type': 'text/html;charset=UTF-8' },
          });
        }

        // Generate OTP & store in KV (expires in 5 min)
        const otp = generateOTP();
        await env.OTP_STORE.put(`otp:${ADMIN_EMAIL}`, otp, { expirationTtl: OTP_EXPIRY });

        // Send OTP via Resend
        const sent = await sendOTPEmail(env, otp);
        if (!sent) {
          return new Response(otpPageHTML('Failed to send OTP. Check Resend config.', null), {
            status: 500, headers: { 'Content-Type': 'text/html;charset=UTF-8' },
          });
        }

        return new Response(otpPageHTML(null, 'OTP sent to your email'), {
          headers: { 'Content-Type': 'text/html;charset=UTF-8' },
        });
      }

      // ── Step 3: Verify OTP + Admin Key (POST /admin/login) ──
      if (url.pathname === '/admin/login' && request.method === 'POST') {
        const fd = await request.formData();
        const submittedOTP = (fd.get('otp') || '').trim();
        const submittedKey = fd.get('admin_key') || '';

        // Verify OTP from KV
        const storedOTP = await env.OTP_STORE.get(`otp:${ADMIN_EMAIL}`);
        if (!storedOTP || storedOTP !== submittedOTP) {
          const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
          console.log(`[AUTH FAIL] Bad OTP, IP: ${ip}`);
          return new Response(otpPageHTML('Invalid or expired OTP', null), {
            status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' },
          });
        }

        // Verify Admin Key (constant-time)
        const a = new TextEncoder().encode(submittedKey);
        const b = new TextEncoder().encode(env.ADMIN_KEY);
        let match = a.length === b.length;
        const len = Math.max(a.length, b.length);
        for (let i = 0; i < len; i++) {
          if ((a[i] || 0) !== (b[i] || 0)) match = false;
        }

        if (!match) {
          const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
          console.log(`[AUTH FAIL] Bad admin key, IP: ${ip}`);
          return new Response(otpPageHTML('Invalid admin key', null), {
            status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' },
          });
        }

        // Delete used OTP
        await env.OTP_STORE.delete(`otp:${ADMIN_EMAIL}`);

        // Create session
        const token = await signSession(
          { role: 'admin', email: ADMIN_EMAIL, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE },
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
          return Response.json({ error: 'Unauthorized' }, { status: 401 });
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
        return Response.json({ results: results.results });
      }

      // ── API: Single submission ──
      if (url.pathname.match(/^\/admin\/api\/submissions\/\d+$/) && request.method === 'GET') {
        const id = url.pathname.split('/').pop();
        const row = await env.DB.prepare('SELECT * FROM submissions WHERE id = ?').bind(id).first();
        if (!row) return new Response('Not found', { status: 404 });
        return Response.json(row);
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
        return Response.json({ ok: true });
      }

      // ── API: Stats ──
      if (url.pathname === '/admin/api/stats' && request.method === 'GET') {
        const stats = await env.DB.prepare(`
          SELECT form_name, status, COUNT(*) as count
          FROM submissions GROUP BY form_name, status
        `).all();
        return Response.json(stats.results);
      }

      return new Response('Not found', { status: 404 });
    }

    return new Response('Not found', { status: 404 });
  },
};