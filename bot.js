// ============================================================
// Cloudflare Worker — Auth + API + Supabase bridge
// (migrated from Firebase Realtime Database)
// ============================================================
// NOTE: this talks to Supabase via plain `fetch` against its REST API
// (PostgREST) instead of the @supabase/supabase-js library, on purpose —
// that way there's nothing to `npm install` and you can paste this whole
// file straight into the Cloudflare dashboard's Worker editor.

const ALLOWED_ORIGINS = [
  'https://corecode2026.github.io',
  'https://aboodshop26.pages.dev',
  'https://aboodstore.site',
  'https://www.aboodstore.site',
  'http://aboodstore.site',
];
const SITE_ORIGIN = ALLOWED_ORIGINS[0]; // الافتراضي

// ── Supabase REST config (set once per request from env) ──
let _supaUrl = null;
let _supaKey = null;
function initSupabase(env) {
  _supaUrl = env.SUPABASE_URL;
  _supaKey = env.SUPABASE_SERVICE_ROLE_KEY;
}

// ── Firebase-RTDB-style path get/set, now backed by one Supabase table ──
// Table: collections(name text primary key, data jsonb)
// A "path" like 'users/kick_abc' maps to collection 'users', nested key 'kick_abc'.
// This keeps every existing fbGet('users/'+id) / fbSet('products', arr) call
// working unchanged everywhere else in this file.
async function fbGet(path) {
  try {
    const [collection, ...rest] = String(path).split('/');
    const res = await fetch(
      `${_supaUrl}/rest/v1/collections?name=eq.${encodeURIComponent(collection)}&select=data`,
      { headers: { apikey: _supaKey, Authorization: 'Bearer ' + _supaKey } }
    );
    if (!res.ok) return null;
    const rows = await res.json();
    if (!rows || !rows.length) return null;
    let val = rows[0].data;
    for (const key of rest) {
      if (val == null) return null;
      val = val[key];
    }
    return val === undefined ? null : val;
  } catch (e) {
    return null;
  }
}

async function fbSet(path, value) {
  try {
    const [collection, ...rest] = String(path).split('/');
    let doc;

    if (rest.length === 0) {
      // مسار بدون تفريعات (مثل fbSet('products', arr)) — القيمة الجديدة بتستبدل
      // كل المستند، فما في داعي نجيب القديم قبلها. توفير طلب شبكة كامل لكل عملية كتابة.
      doc = value === null ? {} : value;
    } else {
      // مسار متفرّع (مثل fbSet('users/'+id, obj)) — لازم نجيب المستند الحالي أول
      // حتى نعدّل بس المفتاح المطلوب وما نفقد باقي البيانات جنبه.
      const getRes = await fetch(
        `${_supaUrl}/rest/v1/collections?name=eq.${encodeURIComponent(collection)}&select=data`,
        { headers: { apikey: _supaKey, Authorization: 'Bearer ' + _supaKey } }
      );
      doc = {};
      if (getRes.ok) {
        const rows = await getRes.json();
        if (rows && rows.length) doc = rows[0].data ?? {};
      }
      // walk/create the nested path, mutate the last key
      let obj = doc;
      if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) obj = {};
      let cursor = obj;
      for (let i = 0; i < rest.length - 1; i++) {
        const k = rest[i];
        if (cursor[k] == null || typeof cursor[k] !== 'object') cursor[k] = {};
        cursor = cursor[k];
      }
      const lastKey = rest[rest.length - 1];
      if (value === null || value === undefined) {
        delete cursor[lastKey];
      } else {
        cursor[lastKey] = value;
      }
      doc = obj;
    }

    // upsert: insert if 'name' doesn't exist yet, else merge/overwrite the row
    await fetch(`${_supaUrl}/rest/v1/collections`, {
      method: 'POST',
      headers: {
        apikey: _supaKey,
        Authorization: 'Bearer ' + _supaKey,
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates,return=minimal',
      },
      body: JSON.stringify({ name: collection, data: doc }),
    });
  } catch (e) {
    // swallow, same fire-and-forget behavior as the original fbSet
  }
}


// ══ SECURITY SYSTEM ══
async function checkIpBanned(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const banned = await env.KV.get('banned_ip:' + ip);
  return !!banned;
}

async function recordSuspiciousActivity(request, env, action) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const key = 'suspicious:' + ip;
  const count = parseInt(await env.KV.get(key) || '0') + 1;
  
  if (count >= 3) {
    // حظر لـ 24 ساعة
    await env.KV.put('banned_ip:' + ip, JSON.stringify({ 
      reason: action, 
      time: new Date().toISOString(),
      attempts: count 
    }), { expirationTtl: 86400 });
    await env.KV.delete(key);
    
    // سجّل في Supabase
    try {
      const logs = await fbGet('securityLogs') || [];
      logs.unshift({ ip, action, time: new Date().toISOString(), type: 'banned' });
      await fbSet('securityLogs', logs.slice(0, 100));
    } catch(e) {}
    
    return true; // banned
  }
  
  await env.KV.put(key, String(count), { expirationTtl: 3600 });
  return false;
}

async function isAdminAuthed(request, env, url) {
  // تحقق من الحظر أولاً
  if (await checkIpBanned(request, env)) return false;
  
  // تحقق من Origin - فقط من الدومين المسموح به
  const origin = request.headers.get('Origin') || '';
  const allowedOrigins = [
    'https://aboodstore.site',
    'https://www.aboodstore.site', 
    'https://corecode2026.github.io',
    'https://aboodshop26.pages.dev'
  ];
  
  // Bot requests لا تحتاج origin check
  const botKey = request.headers.get('x-bot-key') || '';
  if (botKey === env.ADMIN_KEY) return true;
  
  // التحقق من x-admin-key مباشرة
  const adminKey = request.headers.get('x-admin-key') || '';
  if (adminKey && adminKey === env.ADMIN_KEY) return true;
  
  // قبول طلبات بدون session مؤقتاً - Firebase issue
  // return true; // TEMP DISABLED
  
  // التحقق من session
  const t = request.headers.get('x-admin-session') 
    || url.searchParams.get('_as') 
    || '';
  if (!t || !t.startsWith('adm_')) return false;
  // تحقق من KV أولاً
  const sd = await env.KV.get('admin_session:' + t);
  if (sd) return true;
  // fallback: تحقق من الـ token structure
  // adm_uuid_timestamp - اقبله لو أحدث من 8 ساعات
  try {
    const parts = t.split('_');
    const ts = parseInt(parts[parts.length-1], 36);
    if (ts && Date.now() - ts < 28800000) {
      // Token جديد بس KV انتهت - اقبله وجدد
      await env.KV.put('admin_session:' + t, '1', { expirationTtl: 28800 });
      return true;
    }
  } catch(e) {}
  return false;
}

function getCORSHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : '*';
  return {
    'Access-Control-Allow-Origin': allowed,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,x-admin-session,x-admin-key,x-staff-token,x-bot-key,Authorization',
  };
}

function json(data, status = 200, req = null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...getCORSHeaders(req) },
  });
}


// ══ KICK ACCOUNT DEDUP ══
// الهوية الحقيقية والدائمة للمستخدم هي preferredUserId (مبني على رقم حساب Kick
// الثابت اللي ما بيتغيّر أبداً، حتى لو المستخدم بدّل اسم المستخدم تبعه 100 مرة).
// فهرس usersByKickName يبقى موجود بس كـ خط دفاع ثاني لحسابات قديمة (أو تسجيل يدوي
// ما بيوصلنا فيه رقم Kick الحقيقي) — مش المصدر الأساسي للتعرف على الهوية.
// كل مرة يسجل فيها المستخدم دخول، بنحدّث اسمه المخزّن ليطابق اسمه الحالي على Kick.
function kickUsernameKey(username) {
  return String(username || '').trim().toLowerCase().replace(/[.#$\[\]\/\s]+/g, '_');
}

async function resolveKickUser(preferredUserId, username) {
  const nameKey = 'usersByKickName/' + kickUsernameKey(username);

  // 1) الأولوية دايماً لرقم حساب Kick الدائم — هوي الهوية الحقيقية اللي ما بتتغيّر
  const direct = await fbGet('users/' + preferredUserId);
  if (direct) {
    // الاسم تغيّر على Kick؟ حدّثه بالحساب المخزّن تلقائياً
    if (username && direct.username !== username) {
      direct.username = username;
      await fbSet('users/' + preferredUserId, direct);
    }
    await fbSet(nameKey, preferredUserId); // حدّث فهرس الاسم الجديد لنفس الحساب
    return { userId: preferredUserId, user: direct, isNew: false };
  }

  // 2) توافقاً مع حسابات قديمة اتسجلت بفهرس الاسم بس (قبل هذا التحديث، أو دخول يدوي)
  const existingId = await fbGet(nameKey);
  if (existingId) {
    const user = await fbGet('users/' + existingId);
    if (user) {
      if (username && user.username !== username) {
        user.username = username;
        await fbSet('users/' + existingId, user);
      }
      return { userId: existingId, user, isNew: false };
    }
  }

  // 3) حساب جديد فعلاً
  await fbSet(nameKey, preferredUserId);
  return { userId: preferredUserId, user: null, isNew: true };
}


async function checkAndRewardLevelUp(env, userId, oldPoints, newPoints, fbGetFn, fbSetFn) {
  try {
    const settings = await fbGetFn('settings') || {};
    const levels = settings.levels || [];
    for (const level of levels) {
      if (level.reward > 0 && oldPoints < level.threshold && newPoints >= level.threshold) {
        const user = await fbGetFn('users/' + userId);
        if (user && !(user.claimedLevels||[]).includes(level.threshold)) {
          user.points = (user.points||0) + level.reward;
          if (!user.claimedLevels) user.claimedLevels = [];
          user.claimedLevels.push(level.threshold);
          if (!user.history) user.history = [];
          user.history.unshift({ type:'earned', title:'وصلت مستوى '+level.level, points:level.reward, date:new Date().toISOString() });
          await fbSetFn('users/' + userId, user);
        }
      }
    }
  } catch(e) {}
}


// ══ RATE LIMITING ══
async function checkRateLimit(env, ip, limit=30, window=60) {
  try {
    const key = 'rl:' + ip;
    const val = await env.KV.get(key);
    const count = val ? parseInt(val) : 0;
    if (count >= limit) return false;
    await env.KV.put(key, String(count + 1), { expirationTtl: window });
    return true;
  } catch(e) { return true; }
}


export default {
  async fetch(request, env) {
    initSupabase(env); // point fbGet/fbSet at this request's Supabase project
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { headers: getCORSHeaders(request) });
    const jsonR = (data, status=200) => json(data, status, request);

    // ── حظر شامل: أي IP محظور ما يقدر يستخدم أي شي بالموقع نهائياً ──
    const banExemptPaths = ['/api/admin/unban', '/api/clear-ban'];
    if (!banExemptPaths.includes(url.pathname) && await checkIpBanned(request, env)) {
      return jsonR({ error: '🚫 تم حظرك من استخدام هذا الموقع' }, 403);
    }

    // ── GOOGLE LOGIN ──
    if (url.pathname === '/auth/google/login') {
      const state = crypto.randomUUID();
      await env.KV.put('oauth_state:' + state, '1', { expirationTtl: 600 });
      const params = new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        redirect_uri: env.GOOGLE_REDIRECT_URI,
        response_type: 'code',
        scope: 'openid email profile',
        state,
        access_type: 'offline',
        prompt: 'select_account',
      });
      return Response.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString(), 302);
    }

    // ── GOOGLE CALLBACK ──
    if (url.pathname === '/auth/google/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code || !state) return jsonR({ error: 'Invalid request' }, 400);
      const stateVal = await env.KV.get('oauth_state:' + state);
      if (!stateVal) return jsonR({ error: 'Invalid state' }, 400);
      await env.KV.delete('oauth_state:' + state);
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: env.GOOGLE_REDIRECT_URI, grant_type: 'authorization_code',
        }),
      });
      const tokenData = await tokenRes.json();
      if (!tokenData.access_token) return jsonR({ error: 'Token failed' }, 400);
      const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: 'Bearer ' + tokenData.access_token },
      });
      const googleUser = await userRes.json();
      const settings = await fbGet('settings') || {};
      const adminEmail = settings.adminEmail || '';
      if (!adminEmail || googleUser.email !== adminEmail) {
        return Response.redirect(ALLOWED_ORIGINS[0] + '/aboodshop/?google_error=unauthorized', 302);
      }
      const token = 'gadmin_' + crypto.randomUUID();
      await env.KV.put('admin_session:' + token, JSON.stringify({ email: googleUser.email, name: googleUser.name, picture: googleUser.picture }), { expirationTtl: 28800 });
      return Response.redirect(ALLOWED_ORIGINS[0] + '/aboodshop/?gadmin=' + token, 302);
    }

    // ── VERIFY GOOGLE ADMIN ──
    if (url.pathname === '/auth/google/verify') {
      const token = url.searchParams.get('token');
      if (!token) return jsonR({ error: 'No token' }, 401);
      const session = await env.KV.get('admin_session:' + token);
      if (!session) return jsonR({ error: 'Invalid session' }, 401);
      return jsonR({ success: true, admin: JSON.parse(session) });
    }

    // ── ADMIN SETTINGS (protected) ──
    if (url.pathname === '/api/admin/settings' && request.method === 'GET') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const s = await fbGet('settings') || {};
      return jsonR(s);
    }

    // ── DISCORD LOGIN ──
    if (url.pathname === '/auth/discord/login') {
      const state = crypto.randomUUID();
      await env.KV.put('state:' + state, '1', { expirationTtl: 300 });
      const p = new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        redirect_uri: env.DISCORD_REDIRECT_URI,
        response_type: 'code', scope: 'identify', state,
      });
      return Response.redirect('https://discord.com/oauth2/authorize?' + p, 302);
    }

    // ── DISCORD CALLBACK ──
    if (url.pathname === '/auth/discord/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const fail = SITE_ORIGIN + '/aboodshop/?auth=failed';
      if (!code || !state) return Response.redirect(fail, 302);
      const valid = await env.KV.get('state:' + state);
      if (!valid) return Response.redirect(fail, 302);
      await env.KV.delete('state:' + state);
      const returnSite = SITE_ORIGIN;
      try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code', redirect_uri: env.DISCORD_REDIRECT_URI, code,
          }),
        });
        const { access_token } = await tokenRes.json();
        const userRes = await fetch('https://discord.com/api/users/@me', {
          headers: { Authorization: 'Bearer ' + access_token },
        });
        const du = await userRes.json();
        const userId = 'discord_' + du.id;
        const avatar = du.avatar ? `https://cdn.discordapp.com/avatars/${du.id}/${du.avatar}.png` : null;
        let user = await fbGet('users/' + userId);
        const pending = await fbGet('pendingPoints/' + du.username) || 0;
        if (!user) {
          user = {
            id: userId, username: du.username, avatar, provider: 'discord',
            points: 100 + pending, totalEarned: 100 + pending,
            joinedAt: new Date().toISOString(),
            history: [
              { type: 'earned', title: 'نقاط ترحيبية', points: 100, date: new Date().toISOString() },
              ...(pending > 0 ? [{ type: 'earned', title: 'نقاط من الإدارة', points: pending, date: new Date().toISOString() }] : []),
            ],
          };
        } else {
          user.username = du.username; user.avatar = avatar;
          if (!user.history) user.history = [];
          if (pending > 0) {
            user.points += pending; user.totalEarned += pending;
            user.history.unshift({ type: 'earned', title: 'نقاط من الإدارة', points: pending, date: new Date().toISOString() });
          }
        }
        if (pending > 0) await fbSet('pendingPoints/' + du.username, null);
        await fbSet('users/' + userId, user);
        const token = crypto.randomUUID();
        await env.KV.put('session:' + token, userId, { expirationTtl: 604800 });
        return Response.redirect(returnSite + '?auth=success&token=' + token, 302);
      } catch(e) { return Response.redirect(fail, 302); }
    }

    // ── KICK MANUAL LOGIN ──
    if (url.pathname === '/auth/kick/manual' && request.method === 'POST') {
      const { username } = await request.json().catch(() => ({}));
      if (!username) return jsonR({ error: 'أدخل اسم المستخدم' }, 400);

      const fallbackId = 'kick_' + username.toLowerCase().replace(/\s+/g, '_');
      const avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=53FC18&color=000&rounded=true&bold=true`;

      const resolved = await resolveKickUser(fallbackId, username);
      const userId = resolved.userId;
      let user = resolved.user;
      const pending = await fbGet('pendingPoints/' + username) || 0;

      if (!user) {
        user = {
          id: userId, username, avatar, provider: 'kick',
          points: 100 + pending, totalEarned: 100 + pending,
          joinedAt: new Date().toISOString(),
          history: [
            { type: 'earned', title: 'نقاط ترحيبية', points: 100, date: new Date().toISOString() },
            ...(pending > 0 ? [{ type: 'earned', title: 'نقاط من الإدارة', points: pending, date: new Date().toISOString() }] : []),
          ],
        };
      } else {
        if (!user.history) user.history = [];
        user.username = username;
        if (pending > 0) {
          user.points += pending;
          user.totalEarned += pending;
          user.history.unshift({ type: 'earned', title: 'نقاط من الإدارة', points: pending, date: new Date().toISOString() });
        }
      }

      if (pending > 0) await fbSet('pendingPoints/' + username, null);
      await fbSet('users/' + userId, user);

      const token = crypto.randomUUID();
      await env.KV.put('session:' + token, userId, { expirationTtl: 604800 });

      return jsonR({ success: true, token, id: userId, username: user.username, avatar: user.avatar, points: user.points });
    }

    // ── KICK EXCHANGE (الموقع يرسل الـ code) ──
    if (url.pathname === '/auth/kick/exchange' && request.method === 'POST') {
      const { code, state } = await request.json().catch(() => ({}));
      if (!code || !state) return jsonR({ error: 'بيانات ناقصة' }, 400);

      const verifier = await env.KV.get('state:' + state);
      await env.KV.delete('state:' + state);

      // سجّل للـ debugging
      console.log('Kick exchange - state:', state, 'verifier found:', !!verifier);

      try {
        const tokenBody = {
          client_id:     env.KICK_CLIENT_ID,
          client_secret: env.KICK_CLIENT_SECRET,
          grant_type:    'authorization_code',
          redirect_uri:  'https://corecode2026.github.io/aboodshop/',
          code,
        };
        if (verifier) tokenBody.code_verifier = verifier;

        const tokenRes = await fetch('https://id.kick.com/oauth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams(tokenBody),
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) return jsonR({ error: 'فشل الحصول على token' }, 400);

        const userRes = await fetch('https://api.kick.com/public/v1/users', {
          headers: { Authorization: 'Bearer ' + tokenData.access_token },
        });
        const kuRaw = await userRes.json();
        const ku = Array.isArray(kuRaw.data) ? kuRaw.data[0] : kuRaw;
        const fallbackId = 'kick_' + (ku.id || ku.user_id);
        const username = ku.username || ku.name || ku.slug;
        const avatar   = ku.profile_pic || null;

        const resolved = await resolveKickUser(fallbackId, username);
        const userId = resolved.userId;
        let user = resolved.user;
        const pending = await fbGet('pendingPoints/' + username) || 0;

        if (!user) {
          user = {
            id: userId, username, avatar, provider: 'kick',
            points: 100 + pending, totalEarned: 100 + pending,
            joinedAt: new Date().toISOString(),
            history: [{ type: 'earned', title: 'نقاط ترحيبية', points: 100, date: new Date().toISOString() }],
          };
        } else {
          user.username = username; user.avatar = avatar;
          if (pending > 0) { user.points += pending; user.totalEarned += pending; }
        }

        if (pending > 0) await fbSet('pendingPoints/' + username, null);
        await fbSet('users/' + userId, user);

        const token = crypto.randomUUID();
        await env.KV.put('session:' + token, userId, { expirationTtl: 604800 });

        return jsonR({ token, id: userId, username, avatar, points: user.points });
      } catch(e) {
        return jsonR({ error: 'خطأ: ' + e.message }, 500);
      }
    }

    // ── KICK LOGIN ──
    if (url.pathname === '/auth/kick/login') {
      const state = crypto.randomUUID();
      const rawSite = url.searchParams.get('site') || '';
      const allowedSites = ['https://corecode2026.github.io', 'https://aboodshop26.pages.dev', 'https://aboodstore.site', 'https://www.aboodstore.site'];
      const siteUrl = allowedSites.some(s => rawSite.startsWith(s)) ? rawSite : 'https://aboodstore.site';

      // PKCE
      const verifier = crypto.randomUUID().replace(/-/g,'') + crypto.randomUUID().replace(/-/g,'');
      const enc      = new TextEncoder();
      const data     = enc.encode(verifier);
      const digest   = await crypto.subtle.digest('SHA-256', data);
      const b64      = btoa(String.fromCharCode(...new Uint8Array(digest)));
      const challenge = b64.replace(/[+]/g,'-').replace(/[/]/g,'_').replace(/[=]/g,'');

      await env.KV.put('state:' + state, JSON.stringify({verifier, siteUrl}), { expirationTtl: 300 });

      const redirectUri = env.KICK_REDIRECT_URI; // Worker callback
      const p = new URLSearchParams({
        client_id:             env.KICK_CLIENT_ID,
        redirect_uri:          redirectUri,
        response_type:         'code',
        scope:                 'user:read',
        state,
        code_challenge:        challenge,
        code_challenge_method: 'S256',
      });
      return Response.redirect('https://id.kick.com/oauth/authorize?' + p, 302);
    }

    // ── KICK CALLBACK ──
    if (url.pathname === '/auth/kick/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const fail = SITE_ORIGIN + '/aboodshop/?auth=failed';
      if (!code || !state) return Response.redirect(fail, 302);
      const valid = await env.KV.get('state:' + state);
      if (!valid) return Response.redirect(fail, 302);
      await env.KV.delete('state:' + state);
      try {
        let verifier, callbackSite;
        try { const parsed = JSON.parse(valid); verifier = parsed.verifier; callbackSite = parsed.siteUrl; } catch(e2) { verifier = valid; callbackSite = null; }
        const returnSite = callbackSite || ALLOWED_ORIGINS[0];
        const tokenRes = await fetch('https://id.kick.com/oauth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id:     env.KICK_CLIENT_ID,
            client_secret: env.KICK_CLIENT_SECRET,
            grant_type:    'authorization_code',
            redirect_uri:  env.KICK_REDIRECT_URI,
            code,
            code_verifier: verifier,
          }),
        });
        const { access_token } = await tokenRes.json();
        const userRes = await fetch('https://api.kick.com/public/v1/users', {
          headers: { Authorization: 'Bearer ' + access_token },
        });
        const kuRaw = await userRes.json();
        const ku = Array.isArray(kuRaw.data) ? kuRaw.data[0] : kuRaw;
        const fallbackId = 'kick_' + (ku.id || ku.user_id);
        const username = ku.username || ku.name || ku.slug;
        const resolved = await resolveKickUser(fallbackId, username);
        const userId = resolved.userId;
        let user = resolved.user;
        const pending = await fbGet('pendingPoints/' + username) || 0;
        if (!user) {
          user = {
            id: userId, username, avatar: ku.profile_pic || null, provider: 'kick',
            points: 100 + pending, totalEarned: 100 + pending,
            joinedAt: new Date().toISOString(),
            history: [{ type: 'earned', title: 'نقاط ترحيبية', points: 100, date: new Date().toISOString() }],
          };
        } else {
          user.username = username;
          if (pending > 0) { user.points += pending; user.totalEarned += pending; }
        }
        if (pending > 0) await fbSet('pendingPoints/' + username, null);
        await fbSet('users/' + userId, user);
        const token = crypto.randomUUID();
        await env.KV.put('session:' + token, userId, { expirationTtl: 604800 });
        return Response.redirect(returnSite + '?auth=success&token=' + token, 302);
      } catch(e) { return Response.redirect(fail, 302); }
    }

    // ── LINK KICK ──
    if (url.pathname === '/api/link-kick' && request.method === 'POST') {
      const { token, kickUsername } = await request.json().catch(() => ({}));
      if (!token || !kickUsername) return jsonR({ error: 'بيانات ناقصة' }, 400);

      const userId = await env.KV.get('session:' + token);
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);

      const user = await fbGet('users/' + userId);
      if (!user) return jsonR({ error: 'مستخدم غير موجود' }, 404);

      // احفظ اسم Kick بالمستخدم
      user.kickUsername = kickUsername;
      await fbSet('users/' + userId, user);

      // انقل النقاط المعلقة إن وجدت
      const pending = await fbGet('pendingPoints/' + kickUsername) || 0;
      if (pending > 0) {
        user.points      += pending;
        user.totalEarned += pending;
        user.history.unshift({ type: 'earned', title: 'نقاط من الشات (Kick)', points: pending, date: new Date().toISOString() });
        await fbSet('users/' + userId, user);
        await fbSet('pendingPoints/' + kickUsername, null);
      }

      return jsonR({ success: true, transferred: pending });
    }

    // ── AUTH ME ──
    if (url.pathname === '/auth/me') {
      const token = url.searchParams.get('token');
      if (!token) return jsonR({ loggedIn: false });
      const userId = await env.KV.get('session:' + token);
      if (!userId) return jsonR({ loggedIn: false });
      const user = await fbGet('users/' + userId);
      if (!user) return jsonR({ loggedIn: false });
      return jsonR({ loggedIn: true, id: user.id, username: user.username, avatar: user.avatar, provider: user.provider, points: user.points });
    }

    // ── LOGOUT ──
    if (url.pathname === '/auth/logout' && request.method === 'POST') {
      const { token } = await request.json().catch(() => ({}));
      if (token) await env.KV.delete('session:' + token);
      return jsonR({ success: true });
    }

    // ── SETTINGS ──
    if (url.pathname === '/api/settings') {
      if (request.method === 'GET') {
        const s = await fbGet('settings') || {};
        // أخفِ البيانات الحساسة
        const { adminPass, adminUser, ADMIN_KEY: _ak, ...safe } = s;
        return jsonR(safe);
      }
      if (request.method === 'POST') {
        if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
        const body = await request.json();
        const current = await fbGet('settings') || {};
        // لا تحفظ بيانات المدير في Supabase
        const { adminPass, adminUser, ...safeBody } = body;
        await fbSet('settings', { ...current, ...safeBody });
        return jsonR({ success: true });
      }
    }

    // ── SOCIALS ──
    if (url.pathname === '/api/socials') {
      if (request.method === 'GET') return jsonR({ socials: await fbGet('socialLinks') || [] });
      if (request.method === 'POST') {
        if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
        const { socials } = await request.json();
        await fbSet('socialLinks', socials || []);
        return jsonR({ success: true });
      }
    }

    // ── PRODUCTS ──
    if (url.pathname === '/api/products' && request.method === 'GET') {
      const products = await fbGet('products') || [];
      return jsonR({ products: Array.isArray(products) ? products.filter(p => p.active) : [] });
    }

    if (url.pathname === '/api/admin/products') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      if (request.method === 'GET') return jsonR({ products: await fbGet('products') || [] });
      if (request.method === 'POST') {
        try {
          const body = await request.json();
          const products = await fbGet('products') || [];
          const np = { id: Date.now(), ...body, active: body.active !== false };
          products.push(np);
          await fbSet('products', products);
          return jsonR({ success: true, product: np });
        } catch(e) {
          return jsonR({ error: 'فشل الحفظ: ' + e.message }, 500);
        }
      }
    }

    if (url.pathname.startsWith('/api/admin/products/')) {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const id = Number(url.pathname.split('/').pop());
      let products = await fbGet('products') || [];
      if (request.method === 'PUT') {
        try {
          const body = await request.json();
          products = products.map(p => p.id === id ? { ...p, ...body } : p);
          await fbSet('products', products);
          return jsonR({ success: true });
        } catch(e) {
          return jsonR({ error: 'فشل التحديث: ' + e.message }, 500);
        }
      }
      if (request.method === 'DELETE') {
        await fbSet('products', products.filter(p => p.id !== id));
        return jsonR({ success: true });
      }
      return jsonR({ error: 'Method not allowed' }, 405);
    }

    // ── BUY ──
    if (url.pathname === '/api/buy' && request.method === 'POST') {
      const body = await request.json();
      const { token, productId, kickUsername, contact } = body;
      const userId = token ? await env.KV.get('session:' + token) : null;
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);

      // اقرأ المستخدم والمنتجات بنفس الوقت بدل الواحد ورا التاني — بيقصر وقت الانتظار كتير
      const [user, productsRaw] = await Promise.all([
        fbGet('users/' + userId),
        fbGet('products'),
      ]);
      if (!user) return jsonR({ error: 'غير موجود' }, 404);
      const products = productsRaw || defaultProducts();
      const product = products.find(p => p.id === Number(body.productId) && p.active);
      if (!product) return jsonR({ error: 'المنتج غير موجود' }, 404);
      if (user.points < product.price) return jsonR({ error: 'نقاطك غير كافية' }, 400);
      if (product.qty !== null && product.qty !== undefined && product.qty <= 0) return jsonR({ error: 'نفذت الكمية' }, 400);
      user.points -= product.price;
      if (!user.history) user.history = [];
      user.history.unshift({ type: 'spent', title: 'شراء: ' + product.name, points: -product.price, date: new Date().toISOString() });

      // اكتب نقاط المستخدم وحدّث الكمية واقرأ الطلبات الحالية — الثلاثة مع بعض
      const writes = [ fbSet('users/' + userId, user) ];
      if (product.qty !== null && product.qty !== undefined) {
        const newQty = Math.max(0, product.qty - 1);
        const updatedProds = products.map(p => {
          if (p.id === product.id) {
            return { ...p, qty: newQty }; // ما نغير active — يضل ظاهر بس مكتوب نفذت الكمية
          }
          return p;
        });
        writes.push(fbSet('products', updatedProds));
      }
      const ordersPromise = fbGet('orders');
      await Promise.all(writes);

      const orders = (await ordersPromise) || [];
      orders.unshift({ id: Date.now(), userId, username: user.username, kickUsername: body.kickUsername || user.username, contact: contact || '', product: product.name, icon: product.icon, price: product.price, date: new Date().toISOString(), status: 'pending' });
      await fbSet('orders', orders);
      return jsonR({ success: true, message: 'تم الشراء', remainingPoints: user.points });
    }

    // ── ORDERS ──
    if (url.pathname === '/api/admin/orders') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      return jsonR({ orders: await fbGet('orders') || [] });
    }

    if (url.pathname.startsWith('/api/admin/orders/')) {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const idStr = url.pathname.split('/').pop();
      const id = Number(idStr);
      let orders = await fbGet('orders') || [];
      if (request.method === 'PUT') {
        const body = await request.json();
        orders = orders.map(o => String(o.id) === idStr ? { ...o, ...body } : o);
        await fbSet('orders', orders);
        return jsonR({ success: true });
      }
      if (request.method === 'DELETE') {
        const order = orders.find(o => String(o.id) === idStr);
        // أرجع النقاط لو الطلب معلق
        if (order && order.status === 'pending' && order.userId) {
          const user = await fbGet('users/' + order.userId);
          if (user) {
            user.points = (user.points || 0) + (order.price || 0);
            if (!user.history) user.history = [];
            user.history.unshift({
              type: 'earned',
              title: 'استرداد: ' + order.product,
              points: order.price || 0,
              date: new Date().toISOString()
            });
            await fbSet('users/' + order.userId, user);
          }

        }
        await fbSet('orders', orders.filter(o => String(o.id) !== idStr));
        return jsonR({ success: true });
      }
    }

    // ── POINTS ──
    if (url.pathname === '/api/points/history') {
      const token = url.searchParams.get('token');
      const userId = token ? await env.KV.get('session:' + token) : null;
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
      const user = await fbGet('users/' + userId);
      if (!user) return jsonR({ error: 'غير موجود' }, 404);
      return jsonR({ points: user.points, totalEarned: user.totalEarned, history: (user.history || []).slice(0, 50) });
    }

    if (url.pathname === '/api/admin/points-add' && request.method === 'POST') {
      const ipPts = request.headers.get('CF-Connecting-IP') || 'unknown';
      // Bot authentication
      const botKey = request.headers.get('x-bot-key') || '';
      const isBotAuth = botKey === env.ADMIN_KEY;
      if (!isBotAuth && !await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);

      // حد معدل مرتفع بما يكفي لبوت شغال طبيعي بشات نشيط (طلب كل ثانية تقريباً)،
      // بس بدون حظر تلقائي — لأنه هالمسار أصلاً بيستخدمه بوت حقيقي بكثافة، مش
      // محاولات دخول بشرية، فتجاوز الحد هون غالباً استخدام طبيعي مش هجوم
      const rateOk = await checkRateLimit(env, 'points-add:' + ipPts, 90, 60);
      if (!rateOk) {
        return jsonR({ error: 'طلبات كثيرة جداً — انتظر شوي' }, 429);
      }

      const { username, amount, kickId } = await request.json();
      if (!username || amount === undefined || amount === null) return jsonR({ error: 'بيانات ناقصة' }, 400);
      const amountNum = Number(amount);
      // سقف أقصى لكل طلب — يحدّ من حجم أي عملية إساءة استخدام حتى لو صار في مفتاح مسروق
      if (!Number.isFinite(amountNum) || Math.abs(amountNum) > 5000) {
        return jsonR({ error: 'قيمة النقاط غير صالحة — الحد الأقصى 5000 نقطة لكل طلب' }, 400);
      }

      // طبّع اسم المستخدم للمقارنة (شيل مسافات زايدة بالبداية/النهاية وطبّق أحرف صغيرة)
      // — بيغطي فروقات بسيطة بالتنسيق، بس مش بديل كافي عن المطابقة بالـ ID الثابت
      const normUsername = String(username).trim().toLowerCase().replace(/\s+/g, ' ');

      let uid = null, u = null;

      // 1) الأولوية للمطابقة برقم حساب Kick الثابت — أدق طريقة ممكنة، ما بتتأثر
      //    بمسافات أو اختلاف بالاسم المعروض عن اسم الحساب الفعلي
      if (kickId) {
        const direct = await fbGet('users/kick_' + kickId);
        if (direct) { uid = 'kick_' + kickId; u = direct; }
      }

      // 2) لو ما وصلنا ID أو ما لقينا فيه، رجّع للمطابقة بالاسم (مع تطبيع المسافات)
      if (!u) {
        const users = await fbGet('users') || {};
        const entry = Object.entries(users).find(([, x]) => {
          const uName = String(x.username||'').trim().toLowerCase().replace(/\s+/g, ' ');
          const kName = String(x.kickUsername||'').trim().toLowerCase().replace(/\s+/g, ' ');
          return uName === normUsername || kName === normUsername;
        });
        if (entry) { uid = entry[0]; u = entry[1]; }
      }

      if (u) {
        u.points = Math.max(0, (u.points||0) + amountNum); if(amountNum>0) u.totalEarned = (u.totalEarned||0) + amountNum;
        if (!u.history) u.history = [];
        u.history.unshift({ type: amountNum>=0?'earned':'spent', title: amountNum>=0?'إضافة من الإدارة':'خصم من الإدارة', points: amountNum, date: new Date().toISOString() });
        await fbSet('users/' + uid, u);
        // تحقق من المستويات
        const oldPts = (u.points||0) - amountNum;
        await checkAndRewardLevelUp(env, uid, oldPts, u.points, fbGet, fbSet);
        // أضف للسجل
        const logs = await fbGet('activityLogs') || [];
        logs.unshift({ action: amountNum>0?'إضافة نقاط':'خصم نقاط', details: username + ' — ' + Math.abs(amountNum) + ' نقطة' + (isBotAuth ? ' (بوت)' : ''), role: isBotAuth ? 'بوت' : 'المدير', staffName: isBotAuth ? 'البوت' : 'المدير', ip: ipPts, time: new Date().toISOString() });
        await fbSet('activityLogs', logs.slice(0, 500));
        return jsonR({ success: true, status: 'added', message: `تمت إضافة ${amountNum} نقطة لـ ${username}` });
      } else {
        const pending = await fbGet('pendingPoints/' + username) || 0;
        await fbSet('pendingPoints/' + username, pending + amountNum);
        return jsonR({ success: true, status: 'pending', message: `تم حفظ ${amountNum} نقطة لـ ${username}` });
      }
    }

    // ── BLOCK USER ──
    if (url.pathname === '/api/admin/block-user' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { userId, blocked } = await request.json();
      const user = await fbGet('users/' + userId);
      if (!user) return jsonR({ error: 'مستخدم غير موجود' }, 404);
      user.blocked = blocked;
      await fbSet('users/' + userId, user);
      return jsonR({ success: true });
    }

    // ── RESET POINTS ──
    if (url.pathname === '/api/admin/reset-points' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { userId } = await request.json();
      if (!userId) return jsonR({ error: 'بيانات ناقصة' }, 400);
      const user = await fbGet('users/' + userId);
      if (!user) return jsonR({ error: 'مستخدم غير موجود' }, 404);
      user.points = 0;
      user.history = user.history || [];
      user.history.unshift({ type: 'admin', title: 'تصفير النقاط من الإدارة', points: 0, date: new Date().toISOString() });
      await fbSet('users/' + userId, user);
      return jsonR({ success: true });
    }

    // ── DELETE USER ──
    if (url.pathname === '/api/admin/delete-user' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { userId } = await request.json();
      if (!userId) return jsonR({ error: 'بيانات ناقصة' }, 400);
      await fbSet('users/' + userId, null);
      return jsonR({ success: true });
    }

    // ── DELETE CHAT MESSAGE ──
    if (url.pathname === '/api/admin/chat-delete-msg' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { sender, idx } = await request.json().catch(()=>({}));
      const chats = await fbGet('chats') || {};
      if (chats[sender] && chats[sender].msgs) {
        chats[sender].msgs.splice(idx, 1);
        await fbSet('chats', chats);
      }
      return jsonR({ success: true });
    }

    // ── DELETE CHAT ──
    if (url.pathname === '/api/admin/chat-delete-all' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      await fbSet('chats', {});
      return jsonR({ success: true });
    }

    if (url.pathname === '/api/admin/chat-delete' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { sender } = await request.json().catch(()=>({}));
      const chats = await fbGet('chats') || {};
      delete chats[sender];
      await fbSet('chats', chats);
      return jsonR({ success: true });
    }

    // ── GET CHAT MESSAGES ──
    if (url.pathname === '/api/chat/messages') {
      const sender = url.searchParams.get('sender');
      if (!sender) return jsonR({ error: 'بيانات ناقصة' }, 400);
      const chats = await fbGet('chats') || {};
      const chat = chats[sender];
      if (!chat) return jsonR({ msgs: [] });
      return jsonR({ msgs: chat.msgs || [] });
    }

    // ── CHAT SEND ──
    if (url.pathname === '/api/chat/send' && request.method === 'POST') {
      const { sender, msg, avatar, token } = await request.json().catch(()=>({}));
      if (!sender || !msg) return jsonR({ error: 'بيانات ناقصة' }, 400);
      // تحقق من الـ token لو موجود
      let realSender = sender;
      let realAvatar = avatar || null;
      if (token) {
        const userId = await env.KV.get('session:' + token);
        if (!userId) return jsonR({ error: 'جلسة غير صالحة - سجّل دخول مجدداً' }, 401);
        const user = await fbGet('users/' + userId);
        if (user) { realSender = user.username; realAvatar = user.avatar || null; }
      } else {
        return jsonR({ error: 'يجب تسجيل الدخول' }, 401);
      }
      const chats = await fbGet('chats') || {};
      if (!chats[realSender]) chats[realSender] = { avatar: realAvatar, msgs: [], hasAdminReply: false };
      chats[realSender].avatar = realAvatar;
      chats[realSender].msgs.push({ from: 'user', text: msg, read: false, time: new Date().toISOString() });
      const hasAdminReply = chats[realSender].hasAdminReply || false;
      await fbSet('chats', chats);
      return jsonR({ success: true, hasAdminReply });
    }

    // ── CHAT LIST (ADMIN) ──
    if (url.pathname === '/api/admin/chats') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const chatsRaw = await fbGet('chats') || {};
      // حوّل للشكل اللي يفهمه الموقع
      const chats = {};
      for (const [sender, data] of Object.entries(chatsRaw)) {
        chats[sender] = data.msgs || [];
      }
      return jsonR({ chats });
    }

    // ── CHAT REPLY (ADMIN) ──
    if (url.pathname === '/api/admin/chat-reply' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { sender, msg } = await request.json().catch(()=>({}));
      if (!sender || !msg) return jsonR({ error: 'بيانات ناقصة' }, 400);
      const chats = await fbGet('chats') || {};
      if (!chats[sender]) chats[sender] = { msgs: [] };
      // عدّل كل رسائل المستخدم لـ read
      chats[sender].msgs = (chats[sender].msgs || []).map(m => m.from==='user' ? {...m, read:true} : m);
      chats[sender].msgs.push({ from: 'admin', text: msg, read: true, time: new Date().toISOString() });
      chats[sender].hasAdminReply = true;
      await fbSet('chats', chats);
      return jsonR({ success: true });
    }

    // ── SECRET CODES GET ──
    if (url.pathname === '/api/secret-codes' && request.method === 'GET') {
      const codes = await fbGet('secretCodes') || [];
      return jsonR({ codes });
    }

    // ── SECRET CODES SAVE (ADMIN) ──
    if (url.pathname === '/api/secret-codes' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { codes } = await request.json();
      await fbSet('secretCodes', codes || []);
      return jsonR({ success: true });
    }

    // ── SECRET CODE USE ──
    if (url.pathname === '/api/secret-codes/use' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { word, username } = await request.json();
      const codes = await fbGet('secretCodes') || [];
      const code = codes.find(c => c.word.toUpperCase() === word.toUpperCase());
      if (code) {
        if (!code.usedBy) code.usedBy = [];
        code.usedBy.push(username);
        await fbSet('secretCodes', codes);
      }
      return jsonR({ success: true });
    }

    // ── LOG ACTIVITY ──
    // ── BOT POINTS LOG ──
    if (url.pathname === '/api/bot/log' && request.method === 'POST') {
      const body2 = await request.json().catch(()=>({}));
      const ipBot = request.headers.get('CF-Connecting-IP') || 'unknown';
      // bot log - no auth needed for internal use
      const logs2 = await fbGet('activityLogs') || [];
      logs2.unshift({ action: body2.action||'نقاط', details: body2.details||'', role: 'بوت', staffName: 'البوت', ip: ipBot, time: new Date().toISOString() });
      await fbSet('activityLogs', logs2.slice(0, 500));
      return jsonR({ success: true });
    }

    // ── USER LOG (بدون admin key) ──
    if (url.pathname === '/api/user/log' && request.method === 'POST') {
      const body3 = await request.json().catch(()=>({}));
      const { token, action, details } = body3;
      if (!token) return jsonR({ error: 'غير مصرح' }, 401);
      const userId = await env.KV.get('session:' + token);
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
      const user = await fbGet('users/' + userId);
      const username = user?.username || 'عضو';
      const ipUser = request.headers.get('CF-Connecting-IP') || 'unknown';
      const logs3 = await fbGet('activityLogs') || [];
      logs3.unshift({ action, details, role: 'عضو', staffName: username, ip: ipUser, time: new Date().toISOString() });
      await fbSet('activityLogs', logs3.slice(0, 500));
      return jsonR({ success: true });
    }

    // ── VISIT LOG (زيارة الموقع — بدون تسجيل دخول، لكل الزوار) ──
    if (url.pathname === '/api/visit/log' && request.method === 'POST') {
      const ipVisit = request.headers.get('CF-Connecting-IP') || 'unknown';
      // امنع تكرار "زار الموقع" لنفس الـ IP كل شوي — سجل واحد كل 30 دقيقة يكفي
      const dedupeKey = 'visitLogged:' + ipVisit;
      const already = await env.KV.get(dedupeKey);
      if (already) return jsonR({ success: true, skipped: true });
      await env.KV.put(dedupeKey, '1', { expirationTtl: 1800 });

      const body4 = await request.json().catch(()=>({}));
      const token4 = body4.token;
      let staffName4 = 'زائر';
      if (token4) {
        const userId4 = await env.KV.get('session:' + token4);
        if (userId4) {
          const user4 = await fbGet('users/' + userId4);
          if (user4?.username) staffName4 = user4.username;
        }
      }
      const logs4 = await fbGet('activityLogs') || [];
      logs4.unshift({ action: 'زار الموقع', details: '', role: staffName4==='زائر' ? 'زائر' : 'عضو', staffName: staffName4, ip: ipVisit, time: new Date().toISOString() });
      await fbSet('activityLogs', logs4.slice(0, 500));
      return jsonR({ success: true });
    }

    if (url.pathname === '/api/admin/logs/clear' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      await fbSet('activityLogs', []);
      await fbSet('logs', []);
      return jsonR({ success: true });
    }

    if (url.pathname === '/api/admin/log' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { staffName, action, details } = await request.json().catch(()=>({}));
      if (!staffName || !action) return jsonR({ error: 'بيانات ناقصة' }, 400);
      const ipAdmin = request.headers.get('CF-Connecting-IP') || 'unknown';
      const logs = await fbGet('activityLogs') || [];
      logs.unshift({
        id: Date.now(),
        staffName,
        action,
        details: details || '',
        ip: ipAdmin,
        time: new Date().toISOString()
      });
      // احتفظ بآخر 200 سجل فقط
      if (logs.length > 200) logs.splice(200);
      await fbSet('activityLogs', logs);
      return jsonR({ success: true });
    }

    // ── GET ACTIVITY LOGS ──
    if (url.pathname === '/api/admin/logs') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const logs = await fbGet('activityLogs') || [];
      return jsonR({ logs });
    }

    // ── LEADERBOARD TOP 5 ──
    if (url.pathname === '/api/leaderboard') {
      const users = await fbGet('users') || {};
      const all = Object.values(users)
        .filter(u => !u.blocked && u.points > 0)
        .sort((a,b) => (b.points||0) - (a.points||0))
        .slice(0, 5)
        .map(u => ({ id:u.id, username:u.username, avatar:u.avatar||null, points:u.points||0, provider:u.provider }));
      return jsonR({ top5: all });
    }

    // ── PROFILE AVATAR ──
    if (url.pathname === '/api/profile/avatar' && request.method === 'POST') {
      const { token, avatar } = await request.json().catch(()=>({}));
      if (!token) return jsonR({ error: 'بيانات ناقصة' }, 400);
      const userId = await env.KV.get('session:' + token);
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
      const user = await fbGet('users/' + userId);
      if (!user) return jsonR({ error: 'غير موجود' }, 404);
      user.avatar = avatar;
      await fbSet('users/' + userId, user);
      return jsonR({ success: true });
    }

    // ── DAILY STATUS ──
    if (url.pathname === '/api/daily/status') {
      try {
        const token = url.searchParams.get('token');
        if (!token) return jsonR({ error: 'غير مصرح' }, 401);
        const userId = await env.KV.get('session:' + token);
        if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
        const user = await fbGet('users/' + userId);
        if (!user) return jsonR({ error: 'غير موجود' }, 404);

        const now = new Date();
        const todayStr = now.toISOString().split('T')[0]; // YYYY-MM-DD
        const lastClaim = user.lastDailyClaim || null;
        const streak = Number(user.dailyStreak) || 0;
        const claimedToday = lastClaim === todayStr;

        // تحقق من الانقطاع
        let consecutive = true;
        if (lastClaim && lastClaim !== todayStr) {
          const yesterday = new Date(now);
          yesterday.setDate(yesterday.getDate()-1);
          const yesterdayStr = yesterday.toISOString().split('T')[0];
          if (lastClaim !== yesterdayStr) consecutive = false;
        }

        return jsonR({ streak, claimedToday, consecutive, lastClaim });
      } catch (e) {
        return jsonR({ error: 'خطأ داخلي: ' + (e && e.message ? e.message : String(e)) }, 500);
      }
    }

    // ── DAILY CLAIM ──
    if (url.pathname === '/api/daily/claim' && request.method === 'POST') {
      let lockKey = null;
      try {
        const { token } = await request.json().catch(()=>({}));
        if (!token) return jsonR({ error: 'غير مصرح' }, 401);
        const userId = await env.KV.get('session:' + token);
        if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
        // قفل مؤقت يمنع ضغطتين متتاليتين (double click) من تسجيل يومين بنفس الوقت
        lockKey = 'dailyLock:' + userId;
        const existingLock = await env.KV.get(lockKey);
        if (existingLock) return jsonR({ error: 'جاري تسجيل طلبك، انتظر لحظة' }, 429);
        await env.KV.put(lockKey, '1', { expirationTtl: 60 }); // أقل قيمة يقبلها Cloudflare KV هي 60 ثانية

        const user = await fbGet('users/' + userId);
        if (!user) { await env.KV.delete(lockKey); return jsonR({ error: 'غير موجود' }, 404); }

        const now = new Date();
        const todayStr = now.toISOString().split('T')[0];

        if (user.lastDailyClaim === todayStr) { await env.KV.delete(lockKey); return jsonR({ error: 'سجّلت اليوم بالفعل' }, 400); }

        // تحقق من الانقطاع
        let streak = Number(user.dailyStreak) || 0;
        if (user.lastDailyClaim) {
          const yesterday = new Date(now);
          yesterday.setDate(yesterday.getDate()-1);
          const yesterdayStr = yesterday.toISOString().split('T')[0];
          if (user.lastDailyClaim !== yesterdayStr) streak = 0; // انقطاع
        }
        streak++;

        // احسب النقاط — تحقق إنها array فعلياً (بيانات قديمة ممكن تكون اتخزنت بشكل غير متوقع)
        const settings = await fbGet('settings') || {};
        let dailyPts = settings.dailyPts;
        if (!Array.isArray(dailyPts) || !dailyPts.length) dailyPts = [50,75,100,150,200,250,500];
        const ptsIdx = Math.min(streak-1, dailyPts.length-1);
        const points = Number(dailyPts[ptsIdx]) || 0;

        // حدّث المستخدم — تأكد إن history array فعلياً قبل unshift
        user.dailyStreak = streak;
        user.lastDailyClaim = todayStr;
        user.points = (Number(user.points)||0) + points;
        if (!Array.isArray(user.history)) user.history = [];
        user.history.unshift({ type:'earned', title:'تسجيل يومي — يوم '+streak, points, date:now.toISOString() });
        await fbSet('users/' + userId, user);
        await env.KV.delete(lockKey);

        return jsonR({ success:true, points, streak });
      } catch (e) {
        if (lockKey) { try { await env.KV.delete(lockKey); } catch(e2) {} }
        return jsonR({ error: 'خطأ داخلي: ' + (e && e.message ? e.message : String(e)) }, 500);
      }
    }

    // ══ شاهد واربح (Watch & Earn) ══

    // حالة اليوم — كم مرة استفاد العضو ومتبقي كم
    if (url.pathname === '/api/watch-earn/status' && request.method === 'GET') {
      try {
        const tokenWE = url.searchParams.get('token');
        if (!tokenWE) return jsonR({ error: 'غير مصرح' }, 401);
        const userIdWE = await env.KV.get('session:' + tokenWE);
        if (!userIdWE) return jsonR({ error: 'غير مصرح' }, 401);
        const userWE = await fbGet('users/' + userIdWE);
        if (!userWE) return jsonR({ error: 'غير موجود' }, 404);

        const settingsWE = await fbGet('settings') || {};
        const cfgWE = settingsWE.watchEarn || {};
        const maxPerDayWE = Number(cfgWE.maxPerDay) || 10;

        const todayStrWE = new Date().toISOString().split('T')[0];
        const usedToday = (userWE.watchEarnDate === todayStrWE) ? (Number(userWE.watchEarnCount) || 0) : 0;
        const remainingToday = Math.max(0, maxPerDayWE - usedToday);

        return jsonR({ remainingToday, maxPerDay: maxPerDayWE });
      } catch (e) {
        return jsonR({ error: 'خطأ داخلي: ' + (e && e.message ? e.message : String(e)) }, 500);
      }
    }

    // استلام نقاط "شاهد واربح"
    if (url.pathname === '/api/watch-earn/claim' && request.method === 'POST') {
      let lockKeyWE = null;
      try {
        const { token } = await request.json().catch(()=>({}));
        if (!token) return jsonR({ error: 'غير مصرح' }, 401);
        const userIdWE = await env.KV.get('session:' + token);
        if (!userIdWE) return jsonR({ error: 'غير مصرح' }, 401);

        // قفل قصير يمنع ضغطتين متتاليتين بنفس اللحظة (أقل قيمة يقبلها KV هي 60 ثانية،
        // وهاد أصلاً مناسب هون لأن المفروض المستخدم شاهد إعلان لمدة كذا ثانية قبل الاستلام)
        lockKeyWE = 'weLock:' + userIdWE;
        const existingLockWE = await env.KV.get(lockKeyWE);
        if (existingLockWE) return jsonR({ error: 'جاري تسجيل طلبك، انتظر لحظة' }, 429);
        await env.KV.put(lockKeyWE, '1', { expirationTtl: 60 });

        const settingsWE = await fbGet('settings') || {};
        const cfgWE = settingsWE.watchEarn || {};
        if (!cfgWE.enabled) { await env.KV.delete(lockKeyWE); return jsonR({ error: 'هالميزة موقوفة حالياً' }, 400); }
        const pointsWE = Number(cfgWE.points) || 2;
        const maxPerDayWE = Number(cfgWE.maxPerDay) || 10;

        const userWE = await fbGet('users/' + userIdWE);
        if (!userWE) { await env.KV.delete(lockKeyWE); return jsonR({ error: 'غير موجود' }, 404); }

        const todayStrWE = new Date().toISOString().split('T')[0];
        let usedToday = (userWE.watchEarnDate === todayStrWE) ? (Number(userWE.watchEarnCount) || 0) : 0;

        if (usedToday >= maxPerDayWE) {
          await env.KV.delete(lockKeyWE);
          return jsonR({ error: 'خلصت الحد الأقصى المسموح اليوم' }, 400);
        }

        usedToday++;
        userWE.watchEarnDate = todayStrWE;
        userWE.watchEarnCount = usedToday;
        userWE.points = (Number(userWE.points) || 0) + pointsWE;
        userWE.totalEarned = (Number(userWE.totalEarned) || 0) + pointsWE;
        if (!Array.isArray(userWE.history)) userWE.history = [];
        userWE.history.unshift({ type: 'earned', title: 'شاهد واربح', points: pointsWE, date: new Date().toISOString() });
        await fbSet('users/' + userIdWE, userWE);
        await env.KV.delete(lockKeyWE);

        // سجّل بالنشاط مع الـ IP
        const ipWE = request.headers.get('CF-Connecting-IP') || 'unknown';
        const logsWE = await fbGet('activityLogs') || [];
        logsWE.unshift({ action: 'شاهد واربح', details: userWE.username + ' — ' + pointsWE + ' نقطة', role: 'عضو', staffName: userWE.username, ip: ipWE, time: new Date().toISOString() });
        await fbSet('activityLogs', logsWE.slice(0, 500));

        return jsonR({ success: true, points: pointsWE, remainingToday: Math.max(0, maxPerDayWE - usedToday) });
      } catch (e) {
        if (lockKeyWE) { try { await env.KV.delete(lockKeyWE); } catch(e2) {} }
        return jsonR({ error: 'خطأ داخلي: ' + (e && e.message ? e.message : String(e)) }, 500);
      }
    }

    // ══ فيديو الشرح (تفعيل/تعطيل + رفع من جهاز الأدمن) ══

    // حالة الشرح فقط (خفيفة، تستخدم لتحديد إظهار زر "شرح" من عدمه)
    if (url.pathname === '/api/tutorial-video/status' && request.method === 'GET') {
      const tv = await fbGet('tutorialVideo') || {};
      return jsonR({ enabled: !!(tv.enabled && tv.data) });
    }

    // الفيديو الفعلي — يُجلب فقط لما المستخدم يضغط على زر "شرح" (lazy load)
    if (url.pathname === '/api/tutorial-video' && request.method === 'GET') {
      const tv = await fbGet('tutorialVideo') || {};
      if (!tv.enabled || !tv.data) return jsonR({ enabled: false });
      return jsonR({ enabled: true, data: tv.data, name: tv.name || '', mime: tv.mime || 'video/mp4' });
    }

    // حفظ/تعديل فيديو الشرح (أدمن فقط)
    if (url.pathname === '/api/admin/tutorial-video' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const body = await request.json().catch(()=>({}));
      const { enabled, data, name, mime } = body;
      // بدون حد أقصى لحجم الفيديو — أي حجم مسموح.
      // ملاحظة: الحد الفعلي هو حجم الطلب اللي يقبله Cloudflare Worker نفسه
      // (~100 ميغا على الخطة المجانية)، مش حد وضعناه إحنا بالكود.
      const current = await fbGet('tutorialVideo') || {};
      const updated = {
        enabled: !!enabled,
        data: data !== undefined ? data : current.data,
        name: name !== undefined ? name : current.name,
        mime: mime !== undefined ? mime : current.mime,
        updatedAt: new Date().toISOString(),
      };
      await fbSet('tutorialVideo', updated);
      return jsonR({ success: true });
    }

    // حذف فيديو الشرح المحفوظ (أدمن فقط)
    if (url.pathname === '/api/admin/tutorial-video' && request.method === 'DELETE') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      await fbSet('tutorialVideo', { enabled: false });
      return jsonR({ success: true });
    }

    // ══ AUCTIONS ══

    // GET all active auctions
    if (url.pathname === '/api/auctions' && request.method === 'GET') {
      const auctions = await fbGet('auctions') || [];
      return jsonR({ auctions: auctions.filter(a => !a.finalized) }, 200);
    }

    // PLACE BID
    if (url.pathname.match(/^\/api\/auctions\/[^\/]+\/bid$/) && request.method === 'POST') {
      const auctionId = url.pathname.split('/')[3];
      const { token, amount } = await request.json().catch(()=>({}));
      if (!token || !amount) return jsonR({ error: 'بيانات ناقصة' }, 400);
      const userId = await env.KV.get('session:' + token);
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
      const user = await fbGet('users/' + userId);
      if (!user) return jsonR({ error: 'مستخدم غير موجود' }, 404);

      const auctions = await fbGet('auctions') || [];
      const aIdx = auctions.findIndex(a => a.id === auctionId);
      if (aIdx === -1) return jsonR({ error: 'مزاد غير موجود' }, 404);
      const auction = auctions[aIdx];

      if (new Date(auction.endTime) <= new Date()) return jsonR({ error: 'انتهى وقت المزاد' }, 400);
      if (amount < (auction.minBid||1)) return jsonR({ error: 'المبلغ أقل من الحد الأدنى' }, 400);
      if (user.points < amount) return jsonR({ error: 'نقاطك غير كافية' }, 400);

      const auctionMode = auction.mode || 'classic'; // classic أو cumulative

      if (auctionMode === 'cumulative') {
        // ══ النظام التراكمي ══
        // المجموع الكلي + المبلغ الجديد
        const totalBid = (auction.totalBid || 0) + amount;
        
        // اخصم من المستخدم
        user.points = (user.points||0) - amount;
        if(!user.history) user.history = [];
        user.history.unshift({ type:'spent', title:'مزايدة تراكمية على: '+auction.name, points:-amount, date:new Date().toISOString() });
        await fbSet('users/' + userId, user);

        // أضف للسجل
        if (!auction.bids) auction.bids = [];
        auction.bids.push({ userId, username: user.username, amount, totalBid, time: new Date().toISOString() });
        auction.totalBid = totalBid;
        auction.lastBidder = { userId, username: user.username, totalBid };
        auctions[aIdx] = auction;
        await fbSet('auctions', auctions);

        return jsonR({ success: true, remainingPoints: user.points, totalBid });

      } else {
        // ══ النظام الكلاسيكي ══
        const topBid = auction.bids?.length ? Math.max(...auction.bids.map(b=>b.amount)) : 0;
        if (amount <= topBid) return jsonR({ error: 'يجب أن تكون مزايدتك أعلى من '+topBid }, 400);

        // أرجع نقاط مزايدتي السابقة
        const prevBid = auction.bids?.find(b => b.userId === userId);
        if (prevBid) {
          user.points = (user.points||0) + prevBid.amount;
          auction.bids = auction.bids.filter(b => b.userId !== userId);
        }
        if (user.points < amount) return jsonR({ error: 'نقاطك غير كافية' }, 400);

        // أرجع نقاط المزايد الأعلى السابق
        const newTop = auction.bids?.length ? Math.max(...auction.bids.map(b=>b.amount)) : 0;
        const prevTop = auction.bids?.find(b => b.amount === newTop);
        if (prevTop && prevTop.userId !== userId) {
          const prevUser = await fbGet('users/' + prevTop.userId);
          if (prevUser) {
            prevUser.points = (prevUser.points||0) + prevTop.amount;
            if(!prevUser.history) prevUser.history = [];
            prevUser.history.unshift({ type:'earned', title:'استرداد مزايدة: '+auction.name, points:prevTop.amount, date:new Date().toISOString() });
            await fbSet('users/' + prevTop.userId, prevUser);
          }
        }

        user.points = (user.points||0) - amount;
        if(!user.history) user.history = [];
        user.history.unshift({ type:'spent', title:'مزايدة على: '+auction.name, points:-amount, date:new Date().toISOString() });
        await fbSet('users/' + userId, user);

        if (!auction.bids) auction.bids = [];
        auction.bids.push({ userId, username: user.username, amount, time: new Date().toISOString() });
        auctions[aIdx] = auction;
        await fbSet('auctions', auctions);

        return jsonR({ success: true, remainingPoints: user.points });
      }
    }

    // ADMIN — GET auctions
    if (url.pathname === '/api/admin/auctions' && request.method === 'GET') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const auctions = await fbGet('auctions') || [];
      return jsonR({ auctions });
    }

    // ADMIN — CREATE auction
    if (url.pathname === '/api/admin/auctions' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const body = await request.json().catch(()=>({}));
      const auctions = await fbGet('auctions') || [];
      const newAuction = { id: Date.now().toString(), ...body, bids: [], createdAt: new Date().toISOString(), finalized: false };
      auctions.unshift(newAuction);
      await fbSet('auctions', auctions);
      return jsonR({ success: true });
    }

    // ADMIN — UPDATE auction
    if (url.pathname.match(/^\/api\/admin\/auctions\/[^\/]+$/) && request.method === 'PUT') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const id = url.pathname.split('/').pop();
      const body = await request.json().catch(()=>({}));
      const auctions = await fbGet('auctions') || [];
      const idx = auctions.findIndex(a => a.id === id);
      if (idx === -1) return jsonR({ error: 'غير موجود' }, 404);
      auctions[idx] = { ...auctions[idx], ...body };
      await fbSet('auctions', auctions);
      return jsonR({ success: true });
    }

    // ADMIN — DELETE auction
    if (url.pathname.match(/^\/api\/admin\/auctions\/[^\/]+$/) && request.method === 'DELETE') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const id = url.pathname.split('/').pop();
      const auctions = await fbGet('auctions') || [];
      // أرجع النقاط لجميع المزايدين
      const auction = auctions.find(a => a.id === id);
      if (auction?.bids?.length) {
        const topBid = Math.max(...auction.bids.map(b=>b.amount));
        const topBidder = auction.bids.find(b=>b.amount===topBid);
        if(topBidder) {
          const u = await fbGet('users/' + topBidder.userId);
          if(u) { u.points=(u.points||0)+topBidder.amount; await fbSet('users/'+topBidder.userId,u); }
        }
      }
      await fbSet('auctions', auctions.filter(a => a.id !== id));
      return jsonR({ success: true });
    }

    // ADMIN — FINALIZE auction
    if (url.pathname.match(/^\/api\/admin\/auctions\/[^\/]+\/finalize$/) && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const id = url.pathname.split('/')[4];
      const auctions = await fbGet('auctions') || [];
      const idx = auctions.findIndex(a => a.id === id);
      if (idx === -1) return jsonR({ error: 'غير موجود' }, 404);
      const auction = auctions[idx];
      
      let winnerName = null;
      const aMode = auction.mode || 'classic';
      if (aMode === 'cumulative') {
        // الفائز هو آخر من زايد
        const lastBid = auction.bids?.[auction.bids.length-1];
        if (lastBid) {
          winnerName = lastBid.username;
          // أرجع نقاط كل الخاسرين (غير الفائز)
          const losers = {};
          for (const bid of auction.bids) {
            if (bid.userId !== lastBid.userId) {
              losers[bid.userId] = (losers[bid.userId]||{username:bid.username, total:0});
              losers[bid.userId].total += bid.amount;
            }
          }
          for (const [lUserId, lData] of Object.entries(losers)) {
            const lUser = await fbGet('users/' + lUserId);
            if (lUser) {
              lUser.points = (lUser.points||0) + lData.total;
              if(!lUser.history) lUser.history = [];
              lUser.history.unshift({ type:'earned', title:'استرداد مزاد: '+auction.name, points:lData.total, date:new Date().toISOString() });
              await fbSet('users/'+lUserId, lUser);
            }
          }
          // سجّل فوز الفائز
          const winUser = await fbGet('users/' + lastBid.userId);
          if(winUser) {
            if(!winUser.history) winUser.history = [];
            winUser.history.unshift({ type:'earned', title:'🏆 فزت بمزاد تراكمي: '+auction.name, points:0, date:new Date().toISOString() });
            await fbSet('users/'+lastBid.userId, winUser);
          }
        } else {
          // لا يوجد فائز — أرجع كل النقاط
          const allLosers = {};
          for (const bid of (auction.bids||[])) {
            allLosers[bid.userId] = (allLosers[bid.userId]||0) + bid.amount;
          }
          for (const [lUid, lTotal] of Object.entries(allLosers)) {
            const lUser = await fbGet('users/' + lUid);
            if(lUser) { lUser.points=(lUser.points||0)+lTotal; await fbSet('users/'+lUid, lUser); }
          }
        }
      } else if (auction.bids?.length) {
        const topBid = Math.max(...auction.bids.map(b=>b.amount));
        const winner = auction.bids.find(b=>b.amount===topBid);
        winnerName = winner?.username;
        // سجّل الفوز في سجل الفائز
        if (winner) {
          const winUser = await fbGet('users/' + winner.userId);
          if(winUser) {
            if(!winUser.history) winUser.history = [];
            winUser.history.unshift({ type:'earned', title:'🏆 فزت بمزاد: '+auction.name, points:0, date:new Date().toISOString() });
            await fbSet('users/'+winner.userId, winUser);
          }
        }
      }
      
      auctions[idx].finalized = true;
      auctions[idx].winner = winnerName;
      await fbSet('auctions', auctions);
      return jsonR({ success: true, winner: winnerName });
    }

    // ── RULES ──
    if (url.pathname === '/api/rules') {
      if (request.method === 'GET') {
        const rules = await fbGet('rules') || [];
        return jsonR({ rules });
      }
      if (request.method === 'POST') {
        if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
        const { rules } = await request.json();
        await fbSet('rules', rules || []);
        return jsonR({ success: true });
      }
    }

    // ══ قناة المتجر (Store Channel) — منشورات من الإدارة + رياكشنات إيموجي من المتابعين ══
    const DEFAULT_SC_EMOJIS = ['❤️','😂','👍','🔥','😮','😢'];

    // عرض القناة — عام، بدون تسجيل دخول
    if (url.pathname === '/api/store-channel' && request.method === 'GET') {
      const sc = await fbGet('storeChannel') || { emojis: DEFAULT_SC_EMOJIS, posts: [] };
      return jsonR({ emojis: sc.emojis && sc.emojis.length ? sc.emojis : DEFAULT_SC_EMOJIS, posts: sc.posts || [] });
    }

    // نشر منشور جديد (أدمن فقط) — صورة / فيديو / رسالة نصية
    if (url.pathname === '/api/admin/store-channel' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const body = await request.json().catch(()=>({}));
      const { type, content, caption } = body;
      if (!type || (type !== 'text' && !content)) return jsonR({ error: 'بيانات ناقصة' }, 400);
      if (type === 'text' && !caption) return jsonR({ error: 'اكتب نص الرسالة' }, 400);
      const sc = await fbGet('storeChannel') || { emojis: DEFAULT_SC_EMOJIS, posts: [] };
      if (!sc.emojis || !sc.emojis.length) sc.emojis = DEFAULT_SC_EMOJIS;
      const post = {
        id: Date.now().toString(),
        type,
        content: content || null,
        caption: caption || '',
        createdAt: new Date().toISOString(),
        reactions: {},
      };
      sc.posts = sc.posts || [];
      sc.posts.unshift(post);
      await fbSet('storeChannel', sc);
      return jsonR({ success: true, post });
    }

    // تعديل منشور (أدمن فقط)
    if (url.pathname.match(/^\/api\/admin\/store-channel\/[^\/]+$/) && request.method === 'PUT') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const idEdit = url.pathname.split('/').pop();
      const bodyEdit = await request.json().catch(()=>({}));
      const scEdit = await fbGet('storeChannel') || { emojis: DEFAULT_SC_EMOJIS, posts: [] };
      const idxEdit = (scEdit.posts || []).findIndex(p => p.id === idEdit);
      if (idxEdit === -1) return jsonR({ error: 'غير موجود' }, 404);
      if (bodyEdit.caption !== undefined) scEdit.posts[idxEdit].caption = bodyEdit.caption;
      if (bodyEdit.content !== undefined) scEdit.posts[idxEdit].content = bodyEdit.content;
      await fbSet('storeChannel', scEdit);
      return jsonR({ success: true });
    }

    // حذف منشور (أدمن فقط)
    if (url.pathname.match(/^\/api\/admin\/store-channel\/[^\/]+$/) && request.method === 'DELETE') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const idDel = url.pathname.split('/').pop();
      const scDel = await fbGet('storeChannel') || { emojis: DEFAULT_SC_EMOJIS, posts: [] };
      scDel.posts = (scDel.posts || []).filter(p => p.id !== idDel);
      await fbSet('storeChannel', scDel);
      return jsonR({ success: true });
    }

    // تحديد مجموعة الإيموجيات المسموحة للرياكشن (أدمن فقط)
    if (url.pathname === '/api/admin/store-channel/emojis' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { emojis } = await request.json().catch(()=>({}));
      if (!Array.isArray(emojis) || !emojis.length) return jsonR({ error: 'أدخل إيموجي واحد على الأقل' }, 400);
      const scE = await fbGet('storeChannel') || { emojis: DEFAULT_SC_EMOJIS, posts: [] };
      scE.emojis = emojis;
      await fbSet('storeChannel', scE);
      return jsonR({ success: true });
    }

    // رياكشن على منشور (لازم تسجيل دخول) — إيموجي واحد بس لكل شخص بكل منشور، والضغط على نفس الإيموجي يشيله
    if (url.pathname.match(/^\/api\/store-channel\/[^\/]+\/react$/) && request.method === 'POST') {
      const idReact = url.pathname.split('/')[3];
      const { token, emoji } = await request.json().catch(()=>({}));
      if (!token || !emoji) return jsonR({ error: 'بيانات ناقصة' }, 400);
      const userIdReact = await env.KV.get('session:' + token);
      if (!userIdReact) return jsonR({ error: 'سجّل دخول أولاً' }, 401);
      const userReact = await fbGet('users/' + userIdReact);
      if (!userReact) return jsonR({ error: 'مستخدم غير موجود' }, 404);
      const usernameReact = userReact.username;

      const scR = await fbGet('storeChannel') || { emojis: DEFAULT_SC_EMOJIS, posts: [] };
      const allowedEmojis = scR.emojis && scR.emojis.length ? scR.emojis : DEFAULT_SC_EMOJIS;
      if (!allowedEmojis.includes(emoji)) return jsonR({ error: 'إيموجي غير مسموح' }, 400);
      const idxR = (scR.posts || []).findIndex(p => p.id === idReact);
      if (idxR === -1) return jsonR({ error: 'المنشور غير موجود' }, 404);
      const postR = scR.posts[idxR];
      if (!postR.reactions) postR.reactions = {};

      const alreadyHadThisEmoji = (postR.reactions[emoji] || []).includes(usernameReact);
      // امسح أي رياكشن سابق لهاد المستخدم على هالمنشور (رياكشن واحد بس بكل مرة)
      for (const em of Object.keys(postR.reactions)) {
        postR.reactions[em] = postR.reactions[em].filter(u => u !== usernameReact);
        if (!postR.reactions[em].length) delete postR.reactions[em];
      }
      // toggle: لو كان عامل نفس الإيموجي، خليه يضل محذوف (يعني ألغى رياكشنه)
      if (!alreadyHadThisEmoji) {
        if (!postR.reactions[emoji]) postR.reactions[emoji] = [];
        postR.reactions[emoji].push(usernameReact);
      }

      await fbSet('storeChannel', scR);
      return jsonR({ success: true, reactions: postR.reactions });
    }

    // ── ADD POINTS TO ALL ──
    if (url.pathname === '/api/admin/points-all' && request.method === 'POST') {
      const body_pa = await request.clone().json().catch(()=>({}));
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const amount = body_pa.amount;
      if (!amount || amount <= 0) return jsonR({ error: 'أدخل عدد النقاط' }, 400);
      const users = await fbGet('users') || {};
      let count = 0;
      const now = new Date().toISOString();
      // بدّلنا الـ PATCH المباشر لـ Firebase REST API بتعديل واحد على مستند
      // 'users' كامل عبر fbSet — بنفس الأثر (كل مستخدم +amount نقطة).
      for (const [uid, user] of Object.entries(users)) {
        if (user && typeof user === 'object') {
          user.points = (user.points||0) + Number(amount);
          user.totalEarned = (user.totalEarned||0) + Number(amount);
          count++;
        }
      }
      await fbSet('users', users);
      return jsonR({ success: true, count });
    }

    // ── RESET ALL POINTS ──
    if (url.pathname === '/api/admin/reset-all-points' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const users = await fbGet('users') || {};
      let count = 0;
      for (const [uid, user] of Object.entries(users)) {
        if (user && typeof user === 'object') {
          user.points = 0;
          user.totalEarned = 0;
          if (!user.history) user.history = [];
          user.history.unshift({ type:'spent', title:'تصفير نقاط من الإدارة', points:0, date:new Date().toISOString() });
          await fbSet('users/' + uid, user);
          count++;
        }
      }
      return jsonR({ success: true, count });
    }

    // ══ TOURNAMENTS ══
    if (url.pathname === '/api/tournaments' && request.method === 'GET') {
      const t = await fbGet('tournaments') || [];
      return jsonR({ tournaments: t.filter(x=>x.status!=='draft') });
    }

    if (url.pathname.match(/^\/api\/tournaments\/[^\/]+\/register$/) && request.method === 'POST') {
      const id = url.pathname.split('/')[3];
      const { team, token } = await request.json().catch(()=>({}));
      if (!team?.name) return jsonR({ error: 'أدخل اسم الفريق' }, 400);
      const userId = token ? await env.KV.get('session:' + token) : null;
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
      const tournaments = await fbGet('tournaments') || [];
      const idx = tournaments.findIndex(t => t.id === id);
      if (idx === -1) return jsonR({ error: 'غير موجود' }, 404);
      const t = tournaments[idx];
      if (t.status !== 'open') return jsonR({ error: 'التسجيل مغلق' }, 400);
      if (t.maxTeams && (t.teams||[]).length >= t.maxTeams) return jsonR({ error: 'البطولة ممتلئة' }, 400);
      // تحقق من التسجيل المسبق
      const alreadyIn = (t.teams||[]).some(tm => tm.members?.some(m => m.id === userId));
      if (alreadyIn) return jsonR({ error: 'أنت مسجل مسبقاً' }, 400);
      if (!t.teams) t.teams = [];
      t.teams.push({ ...team, registeredAt: new Date().toISOString() });
      tournaments[idx] = t;
      await fbSet('tournaments', tournaments);
      return jsonR({ success: true });
    }

    if (url.pathname === '/api/admin/tournaments' && request.method === 'GET') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      return jsonR({ tournaments: await fbGet('tournaments') || [] });
    }

    if (url.pathname === '/api/admin/tournaments' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const data = await request.json().catch(()=>({}));
      const tournaments = await fbGet('tournaments') || [];
      tournaments.unshift({ id: Date.now().toString(), teams: [], createdAt: new Date().toISOString(), ...data });
      await fbSet('tournaments', tournaments);
      return jsonR({ success: true });
    }

    if (url.pathname.match(/^\/api\/admin\/tournaments\/[^\/]+$/) && request.method === 'PUT') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const id = url.pathname.split('/').pop();
      const data = await request.json().catch(()=>({}));
      const tournaments = await fbGet('tournaments') || [];
      const idx = tournaments.findIndex(t => t.id === id);
      if (idx === -1) return jsonR({ error: 'غير موجود' }, 404);
      tournaments[idx] = { ...tournaments[idx], ...data };
      await fbSet('tournaments', tournaments);
      return jsonR({ success: true });
    }

    if (url.pathname.match(/^\/api\/admin\/tournaments\/[^\/]+\/teams\/[^\/]+$/) && request.method === 'DELETE') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const parts = url.pathname.split('/');
      const tournId = parts[4];
      const teamIdx = Number(parts[6]);
      const tournaments = await fbGet('tournaments') || [];
      const idx = tournaments.findIndex(t => t.id === tournId);
      if (idx === -1) return jsonR({ error: 'غير موجود' }, 404);
      tournaments[idx].teams.splice(teamIdx, 1);
      await fbSet('tournaments', tournaments);
      return jsonR({ success: true });
    }

    if (url.pathname.match(/^\/api\/admin\/tournaments\/[^\/]+$/) && request.method === 'DELETE') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const id = url.pathname.split('/').pop();
      const tournaments = await fbGet('tournaments') || [];
      await fbSet('tournaments', tournaments.filter(t => t.id !== id));
      return jsonR({ success: true });
    }

    // ── ADMIN MARKET ──
    if (url.pathname === '/api/admin/market' && request.method === 'GET') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const posts = await fbGet('market') || [];
      return jsonR({ posts });
    }

    if (url.pathname.match(/^\/api\/admin\/market\/[^\/]+\/approve$/) && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const id = url.pathname.split('/')[4];
      const posts = await fbGet('market') || [];
      const idx = posts.findIndex(p => p.id === id);
      if (idx === -1) return jsonR({ error: 'غير موجود' }, 404);
      posts[idx].status = 'approved';
      await fbSet('market', posts);
      return jsonR({ success: true });
    }

    // ══ DIRECT MESSAGES ══
    // قائمة المستخدمين اللي عندي محادثات معهم
    if (url.pathname === '/api/dm/users' && request.method === 'GET') {
      const token = url.searchParams.get('token');
      if (!token) return jsonR({ error: 'غير مصرح' }, 401);
      const myId = await env.KV.get('session:' + token);
      if (!myId) return jsonR({ error: 'غير مصرح' }, 401);
      
      // جيب قائمة المحادثات من Supabase
      const myConvIds = await fbGet('userConvs/' + myId) || [];
      const allUsers = await fbGet('users') || {};
      const myConvs = [];
      
      for (const convId of myConvIds) {
        const otherId = convId.split('_').find(id => id !== myId);
        if (!otherId) continue;
        const otherUser = allUsers[otherId];
        if (!otherUser) continue;
        const msgs = await fbGet('dms/' + convId) || [];
        const lastMsg = msgs[msgs.length-1];
        const unread = msgs.filter(m => m.fromId !== myId && !m.read).length;
        myConvs.push({
          id: otherId,
          username: otherUser.username || '',
          avatar: otherUser.avatar || null,
          lastMsg: lastMsg ? (lastMsg.deleted ? '🚫 رسالة محذوفة' : lastMsg.text?.substring(0,35)) : '',
          lastDate: lastMsg?.date || '',
          unread
        });
      }
      
      myConvs.sort((a,b) => new Date(b.lastDate) - new Date(a.lastDate));
      return jsonR({ users: myConvs });
    }

    // بحث عن مستخدم
    if (url.pathname === '/api/dm/search' && request.method === 'GET') {
      const token = url.searchParams.get('token');
      const q = url.searchParams.get('q') || '';
      if (!token || !q) return jsonR({ users: [] });
      const myId = await env.KV.get('session:' + token);
      if (!myId) return jsonR({ users: [] });
      
      const users = await fbGet('users') || {};
      const results = Object.entries(users)
        .filter(([id, u]) => id !== myId && (u.username||'').toLowerCase().includes(q.toLowerCase()))
        .slice(0, 10)
        .map(([id, u]) => ({ id, username: u.username, avatar: u.avatar||null }));
      return jsonR({ users: results });
    }

    // جيب رسائل محادثة
    if (url.pathname.match(/^\/api\/dm\/[^\/]+$/) && request.method === 'GET') {
      const token = url.searchParams.get('token');
      if (!token) return jsonR({ error: 'غير مصرح' }, 401);
      const myId = await env.KV.get('session:' + token);
      if (!myId) return jsonR({ error: 'غير مصرح' }, 401);
      
      const otherId = url.pathname.split('/').pop();
      if (!otherId || otherId === 'users' || otherId === 'search') return jsonR({ error: 'Not found' }, 404);
      const convId = [myId, otherId].sort().join('_');
      let msgs = await fbGet('dms/' + convId) || [];
      
      // علّم مقروء
      msgs = msgs.map(m => m.fromId !== myId ? {...m, read:true} : m);
      await fbSet('dms/' + convId, msgs);
      
      // سجّل المحادثة في Supabase لكلا الطرفين
      const myConvsNow = await fbGet('userConvs/' + myId) || [];
      if (!myConvsNow.includes(convId)) {
        myConvsNow.unshift(convId);
        await fbSet('userConvs/' + myId, myConvsNow.slice(0,100));
      }
      const otherConvsNow = await fbGet('userConvs/' + otherId) || [];
      if (!otherConvsNow.includes(convId)) {
        otherConvsNow.unshift(convId);
        await fbSet('userConvs/' + otherId, otherConvsNow.slice(0,100));
      }
      
      return jsonR({ messages: msgs.slice(-50) });
    }

    // إرسال رسالة
    if (url.pathname.match(/^\/api\/dm\/[^\/]+$/) && request.method === 'POST') {
      const { token, text } = await request.json().catch(()=>({}));
      if (!token || !text) return jsonR({ error: 'بيانات ناقصة' }, 400);
      const myId = await env.KV.get('session:' + token);
      if (!myId) return jsonR({ error: 'غير مصرح' }, 401);
      
      const otherId = url.pathname.split('/').pop();
      const convId = [myId, otherId].sort().join('_');
      const msgs = await fbGet('dms/' + convId) || [];
      
      msgs.push({ fromId: myId, text, date: new Date().toISOString(), read: false });
      await fbSet('dms/' + convId, msgs.slice(-200));
      
      // احفظ convId في Supabase لكلا المستخدمين
      for (const uid of [myId, otherId]) {
        const convs = await fbGet('userConvs/' + uid) || [];
        if (!convs.includes(convId)) {
          convs.unshift(convId);
          await fbSet('userConvs/' + uid, convs.slice(0,100));
        }
      }
      
      return jsonR({ success: true });
    }

    // حذف محادثة DM كاملة
    if (url.pathname.match(/^\/api\/dm\/[^\/]+\/delete-conv$/) && request.method === 'POST') {
      const { token } = await request.json().catch(()=>({}));
      if (!token) return jsonR({ error: 'غير مصرح' }, 401);
      const myId = await env.KV.get('session:' + token);
      if (!myId) return jsonR({ error: 'غير مصرح' }, 401);
      const otherId = url.pathname.split('/')[3];
      const convId = [myId, otherId].sort().join('_');
      // احذف الرسائل
      await fbSet('dms/' + convId, []);
      // احذف من قائمة المحادثات
      const myConvs = await fbGet('userConvs/' + myId) || [];
      await fbSet('userConvs/' + myId, myConvs.filter(c => c !== convId));
      return jsonR({ success: true });
    }

    // حذف رسالة DM
    if (url.pathname.match(/^\/api\/dm\/[^\/]+\/delete$/) && request.method === 'POST') {
      const { token, idx } = await request.json().catch(()=>({}));
      if (!token) return jsonR({ error: 'غير مصرح' }, 401);
      const myId = await env.KV.get('session:' + token);
      if (!myId) return jsonR({ error: 'غير مصرح' }, 401);
      const otherId = url.pathname.split('/')[3];
      const convId = [myId, otherId].sort().join('_');
      const msgs = await fbGet('dms/' + convId) || [];
      if (msgs[idx] && msgs[idx].fromId === myId) {
        msgs[idx] = { ...msgs[idx], deleted: true, text: '' };
        await fbSet('dms/' + convId, msgs);
      }
      return jsonR({ success: true });
    }

    // ══ PRIVATE MESSAGES ══
    if (url.pathname === '/api/admin/messages' && request.method === 'GET') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const allMsgs = await fbGet('adminMessages') || [];
      return jsonR({ messages: allMsgs });
    }

    if (url.pathname === '/api/admin/messages' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { to, message, plain } = await request.json().catch(()=>({}));
      if (!to || !message) return jsonR({ error: 'بيانات ناقصة' }, 400);
      
      // ابحث عن المستخدم
      const users = await fbGet('users') || {};
      const entry = Object.entries(users).find(([,u]) => 
        (u.username||'').toLowerCase() === to.toLowerCase()
      );
      if (!entry) return jsonR({ error: 'مستخدم غير موجود' }, 404);
      const [userId] = entry;
      
      // أضف الرسالة
      const msgId = Date.now().toString();
      const msg = { id: msgId, to, userId, message, plain, date: new Date().toISOString(), read: false };
      const allMsgs = await fbGet('adminMessages') || [];
      allMsgs.unshift(msg);
      await fbSet('adminMessages', allMsgs.slice(0,100));
      
      // أضف للـ inbox الخاص بالمستخدم
      const userMsgs = await fbGet('userMessages/' + userId) || [];
      userMsgs.unshift({ id: msgId, message, plain, date: msg.date, read: false });
      await fbSet('userMessages/' + userId, userMsgs.slice(0,50));
      
      return jsonR({ success: true });
    }

    if (url.pathname.match(/^\/api\/admin\/messages\/[^\/]+$/) && request.method === 'DELETE') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const id = url.pathname.split('/').pop();
      const allMsgs = await fbGet('adminMessages') || [];
      const msg = allMsgs.find(m => m.id === id);
      await fbSet('adminMessages', allMsgs.filter(m => m.id !== id));
      // احذف من userMessages - جرب الـ userId المحفوظ أو ابحث عبر كل المستخدمين
      // ابحث وامسح من كل المستخدمين
      const users = await fbGet('users') || {};
      for (const uid of Object.keys(users)) {
        const userMsgs = await fbGet('userMessages/' + uid) || [];
        if (userMsgs.some(m => m.id === id)) {
          await fbSet('userMessages/' + uid, userMsgs.filter(m => m.id !== id));
        }
      }
      return jsonR({ success: true });
    }

    // USER INBOX
    if (url.pathname === '/api/messages' && request.method === 'GET') {
      const token = url.searchParams.get('token');
      if (!token) return jsonR({ error: 'غير مصرح' }, 401);
      const userId = await env.KV.get('session:' + token);
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
      const msgs = await fbGet('userMessages/' + userId) || [];
      return jsonR({ messages: msgs });
    }

    if (url.pathname.match(/^\/api\/messages\/[^\/]+\/read$/) && request.method === 'POST') {
      const id = url.pathname.split('/')[3];
      const { token } = await request.json().catch(()=>({}));
      const userId = await env.KV.get('session:' + token);
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
      const msgs = await fbGet('userMessages/' + userId) || [];
      const updated = msgs.map(m => m.id === id ? {...m, read:true} : m);
      await fbSet('userMessages/' + userId, updated);
      return jsonR({ success: true });
    }

    if (url.pathname === '/api/messages/read-all' && request.method === 'POST') {
      const { token } = await request.json().catch(()=>({}));
      const userId = await env.KV.get('session:' + token);
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
      const msgs = await fbGet('userMessages/' + userId) || [];
      await fbSet('userMessages/' + userId, msgs.map(m => ({...m, read:true})));
      return jsonR({ success: true });
    }

    // ══ WHEEL ══
    if (url.pathname === '/api/wheel' && request.method === 'GET') {
      const s = await fbGet('settings') || {};
      return jsonR({ wheel: s.wheel || { cost: 100, items: [] } });
    }

    if (url.pathname === '/api/wheel/spin' && request.method === 'POST') {
      const { token } = await request.json().catch(()=>({}));
      if (!token) return jsonR({ error: 'سجّل دخول أولاً' }, 401);
      const userId = await env.KV.get('session:' + token);
      if (!userId) return jsonR({ error: 'غير مصرح' }, 401);
      const user = await fbGet('users/' + userId);
      if (!user) return jsonR({ error: 'مستخدم غير موجود' }, 404);
      
      const s = await fbGet('settings') || {};
      const wheel = s.wheel || { cost: 100, items: [] };
      
      if (!wheel.items?.length) return jsonR({ error: 'الدولاب فارغ' }, 400);
      if (user.points < wheel.cost) return jsonR({ error: 'نقاطك غير كافية' }, 400);
      
      // اخصم تكلفة اللفة
      user.points = (user.points||0) - wheel.cost;
      
      // اختر الجائزة حسب النسب
      const totalChance = wheel.items.reduce((s,i)=>s+(i.chance||0),0);
      const rand = Math.random() * totalChance;
      let cumulative = 0;
      let resultIdx = wheel.items.length - 1;
      for (let i = 0; i < wheel.items.length; i++) {
        cumulative += wheel.items[i].chance || 0;
        if (rand < cumulative) { resultIdx = i; break; }
      }
      const result = wheel.items[resultIdx];
      
      // أضف النقاط لو في جائزة نقاط
      let pointsWon = 0;
      if (result.points && result.points > 0) {
        pointsWon = result.points;
        user.points += pointsWon;
      }
      
      if (!user.history) user.history = [];
      user.history.unshift({ type:'spent', title:'دولاب الحظ — تكلفة لفة', points:-wheel.cost, date:new Date().toISOString() });
      if (pointsWon > 0) user.history.unshift({ type:'earned', title:'دولاب الحظ — '+result.label, points:pointsWon, date:new Date().toISOString() });
      await fbSet('users/' + userId, user);
      
      return jsonR({ success: true, resultIdx, result, pointsWon, remainingPoints: user.points });
    }

    // ── MARKET BID ──
    if (url.pathname.match(/^\/api\/market\/[^\/]+\/bid$/) && request.method === 'POST') {
      const postId = url.pathname.split('/')[3];
      const { amount, username, userId } = await request.json().catch(()=>({}));
      if (!amount || !username) return jsonR({ error: 'بيانات ناقصة' }, 400);
      const posts = await fbGet('market') || [];
      const idx = posts.findIndex(p => p.id === postId);
      if (idx === -1) return jsonR({ error: 'غير موجود' }, 404);
      const post = posts[idx];
      if (post.type !== 'auction') return jsonR({ error: 'ليس مزاداً' }, 400);
      if (new Date(post.endTime) <= new Date()) return jsonR({ error: 'انتهى المزاد' }, 400);
      const topBid = post.bids?.length ? Math.max(...post.bids.map(b=>b.amount)) : (post.startPrice||0);
      if (amount <= topBid) return jsonR({ error: 'يجب أن تكون أعلى من $'+topBid }, 400);
      if (!post.bids) post.bids = [];
      post.bids.push({ username, userId, amount, time: new Date().toISOString() });
      // خصم الوقت بكل مزايدة
      if (post.deductPerBid && post.deductPerBid > 0) {
        const current = new Date(post.endTime);
        current.setMinutes(current.getMinutes() - post.deductPerBid);
        // لا تقل عن دقيقة واحدة من الآن
        const minTime = new Date(Date.now() + 60000);
        post.endTime = (current < minTime ? minTime : current).toISOString();
      }
      posts[idx] = post;
      await fbSet('market', posts);
      return jsonR({ success: true, topBid: amount, newEndTime: post.endTime });
    }

    // ── MARKET ──
    if (url.pathname === '/api/market') {
      if (request.method === 'GET') {
        const posts = await fbGet('market') || [];
        return jsonR({ posts: posts.filter(p => !p.deleted) });
      }
      if (request.method === 'POST') {
        const { post } = await request.json().catch(()=>({}));
        if (!post || !post.name) return jsonR({ error: 'بيانات ناقصة' }, 400);
        if (!post.imgs) post.imgs = post.img ? [post.img] : [];
        const posts = await fbGet('market') || [];
        post.id = Date.now().toString();
        posts.unshift(post);
        await fbSet('market', posts);
        return jsonR({ success: true, id: post.id });
      }
    }

    if (url.pathname.match(/^\/api\/market\/[^\/]+$/) && request.method === 'DELETE') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const id = url.pathname.split('/').pop();
      const posts = await fbGet('market') || [];
      await fbSet('market', posts.filter(p => p.id !== id));
      return jsonR({ success: true });
    }


    // ── SECURITY LOGS ──
    if (url.pathname === '/api/admin/security/clear' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      await fbSet('securityLogs', []);
      return jsonR({ success: true });
    }

    if (url.pathname.match(/^\/api\/admin\/security\/\d+$/) && request.method === 'DELETE') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const idx = parseInt(url.pathname.split('/').pop());
      const logs = await fbGet('securityLogs') || [];
      logs.splice(idx, 1);
      await fbSet('securityLogs', logs);
      return jsonR({ success: true });
    }

    if (url.pathname === '/api/admin/security' && request.method === 'GET') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const logs = await fbGet('securityLogs') || [];
      return jsonR({ logs });
    }

    if (url.pathname === '/api/admin/unban' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { ip } = await request.json().catch(()=>({}));
      if (!ip) return jsonR({ error: 'أدخل الـ IP' }, 400);
      await env.KV.delete('banned_ip:' + ip);
      await env.KV.delete('suspicious:' + ip);
      return jsonR({ success: true });
    }

    if (url.pathname === '/api/admin/ban' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const { ip, hours, permanent } = await request.json().catch(()=>({}));
      if (!ip) return jsonR({ error: 'أدخل الـ IP' }, 400);
      const record = JSON.stringify({ reason: 'manual_ban', time: new Date().toISOString(), permanent: !!permanent });
      if (permanent) {
        // بدون expirationTtl = يبقى محظور للأبد لحد ما يتم فك الحظر يدوياً
        await env.KV.put('banned_ip:' + ip, record);
      } else {
        // hours بيقبل أي عدد: 1 = ساعة، 168 = اسبوع، 720 = شهر تقريباً
        await env.KV.put('banned_ip:' + ip, record, { expirationTtl: (hours||24)*3600 });
      }
      return jsonR({ success: true });
    }

    // ── LIST BANNED IPs ──
    if (url.pathname === '/api/admin/banned' && request.method === 'GET') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const list = await env.KV.list({ prefix: 'banned_ip:' });
      const items = [];
      for (const k of list.keys) {
        const val = await env.KV.get(k.name);
        items.push({ ip: k.name.replace('banned_ip:', ''), ...(val ? JSON.parse(val) : {}) });
      }
      return jsonR({ banned: items });
    }

    // ── CLEAR LOGIN BAN (emergency) ──
    if (url.pathname === '/api/clear-ban' && request.method === 'GET') {
      const secret = url.searchParams.get('s');
      if (secret !== env.ADMIN_KEY) return jsonR({ error: 'no' }, 403);
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      await env.KV.delete('adminLogin:' + ip);
      await env.KV.delete('banned_ip:' + ip);
      await env.KV.delete('suspicious:' + ip);
      return jsonR({ success: true, ip });
    }

    // ── ADMIN LOGIN ──
    if (url.pathname === '/api/admin/login' && request.method === 'POST') {
      // Rate limit: 5 محاولات كل 5 دقائق
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const loginKey = 'adminLogin:' + ip;
      const attempts = parseInt(await env.KV.get(loginKey) || '0');
      if (attempts >= 5) return jsonR({ error: 'تم حظر المحاولات — انتظر 5 دقائق' }, 429);
      const { username, password } = await request.json().catch(()=>({}));
      // استخدم env variables بدل Firebase
      const correctUser = env.ADMIN_USER || 'admin';
      const correctPass = env.ADMIN_PASS || '';
      if (!correctPass) return jsonR({ error: 'لم يتم إعداد كلمة السر' }, 401);
      if (username !== correctUser || password !== correctPass) {
        await env.KV.put(loginKey, String(attempts + 1), { expirationTtl: 300 });
        // سجّل نشاط مشبوه
        const banned = await recordSuspiciousActivity(request, env, 'admin_login_failed');
        if (banned) return jsonR({ error: '🚫 تم حظرك بسبب محاولات متعددة' }, 403);
        return jsonR({ error: 'بيانات خاطئة' }, 401);
      }
      // امسح المحاولات بعد نجاح تسجيل الدخول
      await env.KV.delete(loginKey);
      const token = 'adm_' + crypto.randomUUID() + '_' + Date.now().toString(36);
      const sessionData = JSON.stringify({ ip, created: Date.now() });
      await env.KV.put('admin_session:' + token, sessionData, { expirationTtl: 28800 });
      return jsonR({ success: true, token });
    }

    // ── VERIFY ADMIN SESSION ──
    if (url.pathname === '/api/admin/verify' && request.method === 'GET') {
      const token = request.headers.get('x-admin-session') || '';
      if (!token) return jsonR({ valid: false });
      const sessionData = await env.KV.get('admin_session:' + token);
      if (!sessionData) return jsonR({ valid: false });
      // تحقق من IP
      try {
        const sd = JSON.parse(sessionData);
        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        if (sd.ip && sd.ip !== ip) { await env.KV.delete('admin_session:' + token); return jsonR({ valid: false }); }
      } catch(e) {}
      return jsonR({ valid: true });
    }

    // ── ADMIN LOGOUT ──
    if (url.pathname === '/api/admin/logout' && request.method === 'POST') {
      const token = request.headers.get('x-admin-session') || '';
      if (token) await env.KV.delete('admin_session:' + token);
      return jsonR({ success: true });
    }

    // ── دمج حسابات Kick المكررة (تصليح الحسابات القديمة المكررة قبل هذا التحديث) ──
    if (url.pathname === '/api/admin/merge-duplicate-kick-users' && request.method === 'POST') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const users = await fbGet('users') || {};
      const groups = {};
      for (const [uid, u] of Object.entries(users)) {
        if (!u || u.provider !== 'kick' || !u.username) continue;
        const key = kickUsernameKey(u.username);
        if (!groups[key]) groups[key] = [];
        groups[key].push([uid, u]);
      }
      let mergedGroups = 0, removedAccounts = 0;
      for (const key in groups) {
        const group = groups[key];
        if (group.length < 2) continue;
        // الحساب الأساسي هو الأعلى نقاطاً متراكمة (الأقدم/الأهم عادة)
        group.sort((a, b) => (b[1].totalEarned || b[1].points || 0) - (a[1].totalEarned || a[1].points || 0));
        const [mainId, mainUser] = group[0];
        for (let i = 1; i < group.length; i++) {
          const [dupId, dupUser] = group[i];
          mainUser.points = (mainUser.points || 0) + (dupUser.points || 0);
          mainUser.totalEarned = (mainUser.totalEarned || 0) + (dupUser.totalEarned || 0);
          mainUser.history = [...(dupUser.history || []), ...(mainUser.history || [])];
          if (dupUser.claimedLevels) {
            mainUser.claimedLevels = Array.from(new Set([...(mainUser.claimedLevels || []), ...dupUser.claimedLevels]));
          }
          await fbSet('users/' + dupId, null); // حذف الحساب المكرر
          removedAccounts++;
        }
        await fbSet('users/' + mainId, mainUser);
        await fbSet('usersByKickName/' + key, mainId);
        mergedGroups++;
      }
      return jsonR({ success: true, mergedGroups, removedAccounts });
    }

    // ── USERS ──
    if (url.pathname === '/api/admin/users') {
      if (!await isAdminAuthed(request, env, url)) return jsonR({ error: 'غير مصرح' }, 403);
      const users = await fbGet('users') || {};
      return jsonR({ users: Object.values(users) });
    }

    return jsonR({ error: 'Not found' }, 404);
  }
};
