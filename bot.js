// ============================================================
// Kick Chat Bot — نقاط تلقائية من الشات والفولو والدعم
// ============================================================
const WebSocket = require('ws');
const fetch     = require('node-fetch');

const KICK_CHANNEL   = process.env.KICK_CHANNEL   || 'Aboodadwan7';
const WORKER_URL     = process.env.WORKER_URL     || 'https://storekick1-auth.hk983480.workers.dev';
const ADMIN_KEY      = process.env.ADMIN_KEY      || 'kickadmin2026secret';
const POINTS_MSG     = Number(process.env.POINTS_MSG)    || 5;    // نقاط لكل رسالة
const POINTS_FOLLOW  = Number(process.env.POINTS_FOLLOW) || 50;   // نقاط الفولو
const POINTS_SUB     = Number(process.env.POINTS_SUB)    || 500;  // نقاط السبسكريب
const POINTS_GIFT    = Number(process.env.POINTS_GIFT)   || 200;  // نقاط الـ Gift sub
const COOLDOWN_MIN   = Number(process.env.COOLDOWN_MIN)  || 2;    // كولداون الشات
const MAX_HR         = Number(process.env.MAX_HR)        || 100;  // حد أقصى في الساعة

// تتبع المستخدمين
const cooldowns = new Map();
const hourly    = new Map();

// ── نضيف نقاط عبر الـ Worker ──
async function addPoints(username, amount, reason) {
  try {
    const res = await fetch(`${WORKER_URL}/api/admin/points-add`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'x-admin-key': ADMIN_KEY },
      body:    JSON.stringify({ username, amount }),
    });
    const d = await res.json();
    console.log(`⭐ ${username} +${amount} نقطة (${reason}) | ${d.status === 'added' ? '✅ أضيفت' : '⏳ محفوظة'}`);
  } catch(e) {
    console.error(`❌ فشل إضافة نقاط لـ ${username}:`, e.message);
  }
}

// ── كولداون الشات ──
function canEarn(username) {
  const now = Date.now();
  const cd  = COOLDOWN_MIN * 60 * 1000;
  const last = cooldowns.get(username) || 0;
  if (now - last < cd) return false;

  let hr = hourly.get(username) || { pts: 0, reset: now + 3600000 };
  if (now > hr.reset) hr = { pts: 0, reset: now + 3600000 };
  if (hr.pts >= MAX_HR) return false;
  return true;
}

function markEarned(username, pts) {
  cooldowns.set(username, Date.now());
  let hr = hourly.get(username) || { pts: 0, reset: Date.now() + 3600000 };
  hr.pts += pts;
  hourly.set(username, hr);
}

// ── جيب معلومات القناة ──
async function getChannelInfo() {
  try {
    const res  = await fetch(`https://kick.com/api/v2/channels/${KICK_CHANNEL}`);
    const data = await res.json();
    const id   = data?.chatroom?.id;
    if (!id) throw new Error('ما لقينا الـ chatroom');
    console.log(`✅ قناة: ${KICK_CHANNEL} | Chatroom ID: ${id}`);
    return id;
  } catch(e) {
    console.error('❌ فشل جلب القناة:', e.message);
    return null;
  }
}

// ── اتصال WebSocket ──
async function connect() {
  const chatroomId = await getChannelInfo();
  if (!chatroomId) {
    console.log('🔄 إعادة المحاولة بعد 30 ثانية...');
    setTimeout(connect, 30000);
    return;
  }

  const PUSHER_KEY = '32cbd69e4b950bf97679';
  const ws = new WebSocket(`wss://ws-us2.pusher.com/app/${PUSHER_KEY}?protocol=7&client=js&version=7.6.0&flash=false`);

  ws.on('open', () => {
    console.log('🔌 متصل بـ Pusher');
    // اشترك بقناة الشات
    ws.send(JSON.stringify({ event: 'pusher:subscribe', data: { auth: '', channel: `chatrooms.${chatroomId}.v2` } }));
    // اشترك بأحداث القناة (فولو، سب)
    ws.send(JSON.stringify({ event: 'pusher:subscribe', data: { auth: '', channel: `channel.${chatroomId}` } }));
  });

  ws.on('message', async (raw) => {
    try {
      const msg  = JSON.parse(raw.toString());
      const data = typeof msg.data === 'string' ? JSON.parse(msg.data) : msg.data;
      if (!data) return;

      // ── رسالة شات ──
      if (msg.event === 'App\\Events\\ChatMessageEvent') {
        const username = data?.sender?.username;
        const text     = data?.content;
        if (!username || !text || text.length < 2) return;

        console.log(`💬 ${username}: ${text.substring(0, 50)}`);

        if (canEarn(username)) {
          await addPoints(username, POINTS_MSG, 'رسالة شات');
          markEarned(username, POINTS_MSG);
        }
      }

      // ── فولو جديد ──
      if (msg.event === 'App\\Events\\FollowersUpdated' || msg.event === 'App\\Events\\UserFollowsChannel') {
        const username = data?.user?.username || data?.username;
        if (!username) return;
        console.log(`❤️ فولو جديد: ${username}`);
        await addPoints(username, POINTS_FOLLOW, 'فولو');
      }

      // ── سبسكريب/دعم ──
      if (msg.event === 'App\\Events\\SubscriptionEvent' || msg.event === 'App\\Events\\StreamerIsLive') {
        const username = data?.user?.username || data?.username;
        if (!username) return;
        const isGift = data?.is_gift || false;
        const pts    = isGift ? POINTS_GIFT : POINTS_SUB;
        console.log(`💎 سب${isGift ? ' (هدية)' : ''}: ${username}`);
        await addPoints(username, pts, isGift ? 'Gift Sub' : 'سبسكريب');
      }

      // ── Superchat/دعم مالي ──
      if (msg.event === 'App\\Events\\LuckyUsersWhoGotGiftSubscriptionsEvent') {
        const users = data?.usernames || [];
        for (const username of users) {
          console.log(`🎁 Gift Sub لـ: ${username}`);
          await addPoints(username, POINTS_GIFT, 'Gift Sub');
        }
      }

      // Ping/Pong
      if (msg.event === 'pusher:ping') {
        ws.send(JSON.stringify({ event: 'pusher:pong', data: {} }));
      }

    } catch(e) { /* تجاهل أخطاء الـ parse */ }
  });

  ws.on('close', (code) => {
    console.log(`🔴 انقطع (${code}) — إعادة الاتصال بعد 10 ثواني...`);
    setTimeout(connect, 10000);
  });

  ws.on('error', (e) => console.error('❌ WS Error:', e.message));

  // Ping كل 30 ثانية
  setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ event: 'pusher:ping', data: {} }));
    }
  }, 30000);
}

// ── تشغيل ──
console.log('🤖 Kick Bot يبدأ...');
console.log(`📡 القناة: ${KICK_CHANNEL}`);
console.log(`💬 نقاط رسالة: ${POINTS_MSG} | ❤️ فولو: ${POINTS_FOLLOW} | 💎 سب: ${POINTS_SUB}`);
console.log('─────────────────────────────────');
connect();
