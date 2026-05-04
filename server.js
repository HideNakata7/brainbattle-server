const express   = require('express');
const http      = require('http');
const { Server } = require('socket.io');
const cors      = require('cors');
const { createClient } = require('@supabase/supabase-js');
// Chargement des variables d'environnement depuis .env
try { require('dotenv').config(); } catch(e) {}
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;

// ── Web Push ──
let webpush = null;
try {
  webpush = require('web-push');
  const VAPID_PUBLIC  = process.env.VAPID_PUBLIC_KEY;
  const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY;
  if (VAPID_PUBLIC && VAPID_PRIVATE) {
    webpush.setVapidDetails('mailto:contact@mindimpact.online', VAPID_PUBLIC, VAPID_PRIVATE);
    console.log('✅ Web Push initialisé');
  } else {
    console.warn('⚠ VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY manquants — push notifications désactivées');
    webpush = null;
  }
} catch(e) { console.warn('⚠ web-push non disponible:', e.message); }

// ── Cron hebdomadaire ──
let cron = null;
try { cron = require('node-cron'); } catch(e) { console.warn('⚠ node-cron non disponible'); }

// Modération & détection de triche (nécessite ANTHROPIC_API_KEY)
let moderation, cheatDetection;
try {
  moderation = require('./moderation');
  cheatDetection = require('./cheat_detection');
  if (!process.env.ANTHROPIC_API_KEY) console.warn('⚠ ANTHROPIC_API_KEY manquant — modération en mode pre-filter seul.');
} catch(e) {
  console.warn('⚠ Modules moderation/cheat_detection non chargés:', e.message);
}

// Supabase — questions FR (anon — lecture publique)
const SUPA_URL = 'https://gqjcmjncyhcioxvjkasc.supabase.co';
const supa = createClient(
  SUPA_URL,
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdxamNtam5jeWhjaW94dmprYXNjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM3NjQ4NjksImV4cCI6MjA4OTM0MDg2OX0.wvpLAEkUKHlcV1Js4ZDjT91u9RCRIL60EKGNwH8RjYA'
);

// Supabase admin (service_role) — pour les écritures sensibles bypassant RLS
const SUPA_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supaAdmin = SUPA_SERVICE_KEY ? createClient(SUPA_URL, SUPA_SERVICE_KEY) : supa;
if (!SUPA_SERVICE_KEY) console.warn('⚠ SUPABASE_SERVICE_ROLE_KEY manquant — endpoints sensibles utilisent anon.');

const CAT_MAP = {
  '9':'General Knowledge','10':'Entertainment: Books','11':'Entertainment: Film',
  '12':'Entertainment: Music','14':'Entertainment: Television','15':'Entertainment: Video Games',
  '17':'Science & Nature','18':'Science: Computers','21':'Sports','22':'Geography',
  '23':'History','25':'Art','27':'Animals','31':'Entertainment: Japanese Anime & Manga',
};
let stripe;
try { stripe = require('stripe')(STRIPE_SECRET); } catch(e) { console.warn('Stripe not installed. Run: npm install stripe'); }

const app    = express();
const server = http.createServer(app);
const ALLOWED_ORIGINS = [
  'https://brainbattle-client.vercel.app',
  'https://mindimpact.online',
  'https://www.mindimpact.online',
  'https://brainbattle.fr',
  'https://www.brainbattle.fr',
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'capacitor://localhost',
  'http://localhost'
];
const io     = new Server(server, {
  cors: { origin: ALLOWED_ORIGINS, methods: ['GET','POST'] }
});

app.use(cors({ origin: ALLOWED_ORIGINS }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ── HTTP rate limiter (in-memory, par IP) ──
const httpRateLimitData = {}; // ip+route → { count, windowStart }
function httpRateLimit(maxPerMinute = 60) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    const key = ip + ':' + req.path;
    const now = Date.now();
    const entry = httpRateLimitData[key];
    if (!entry || now - entry.windowStart > 60000) {
      httpRateLimitData[key] = { count: 1, windowStart: now };
      return next();
    }
    entry.count++;
    if (entry.count > maxPerMinute) {
      res.status(429).json({ error: 'rate_limited', retry_after: Math.ceil((60000 - (now - entry.windowStart))/1000) });
      return;
    }
    next();
  };
}
// Cleanup périodique (toutes les 10 min, supprime les entrées vieilles)
setInterval(() => {
  const cutoff = Date.now() - 120000;
  for (const k of Object.keys(httpRateLimitData)) {
    if (httpRateLimitData[k].windowStart < cutoff) delete httpRateLimitData[k];
  }
}, 600000);

// Stripe webhook needs raw body — must be BEFORE express.json()
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) { res.status(500).send('Webhook not configured'); return; }
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch(e) {
    console.error('⚠️ Webhook signature failed:', e.message);
    return res.status(400).send('Webhook Error: ' + e.message);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const { userId, product } = session.metadata || {};
    if (!userId || !product) { res.json({ received: true }); return; }

    console.log('💰 Payment confirmed:', product, 'for user', userId);

    // Mind Pass : 30 jours d'accès à partir du paiement
    let expiresAt = null;
    if (product === 'pass_monthly') {
      expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    }

    // Store in Supabase (with idempotency check)
    try {
      // Check if this session was already processed
      const { data: existing } = await supa.from('purchases').select('id').eq('stripe_session_id', session.id);
      if (existing && existing.length > 0) {
        console.log('⚠️ Webhook already processed for session:', session.id);
        res.json({ received: true }); return;
      }
      const { error } = await supa.from('purchases').insert({
        user_id: userId,
        product: product,
        stripe_session_id: session.id,
        status: 'completed',
        expires_at: expiresAt
      });
      if (error) console.error('Supabase insert error:', error.message);
      else console.log('✅ Purchase saved to DB:', product);
    } catch(e) {
      console.error('DB error:', e.message);
    }
  }

  res.json({ received: true });
});

app.use(express.json());
app.get('/', (req, res) => res.send('Mind Impact Server ✅'));

// ── VERIFY PURCHASES (with auth token) ──
app.get('/api/purchases/:userId', httpRateLimit(30), async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId) { res.status(400).json({ error: 'Missing userId' }); return; }

    // Verify auth token
    // Strict auth required — token must match userId
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Authentication required' }); return;
    }
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await supa.auth.getUser(token);
    if (authError || !user || user.id !== userId) {
      res.status(403).json({ error: 'Unauthorized' }); return;
    }

    const { data, error } = await supa.from('purchases')
      .select('product, status, expires_at, created_at')
      .eq('user_id', userId)
      .eq('status', 'completed');

    if (error) { res.status(500).json({ error: error.message }); return; }

    const now = new Date();
    const active = (data || []).filter(p => {
      if (!p.expires_at) return true;
      return new Date(p.expires_at) > now;
    });

    const hasPremium = active.some(p => p.product.startsWith('pass_'));
    const premiumExpiry = active.find(p => p.product.startsWith('pass_'))?.expires_at || null;
    const unlockedItems = active.filter(p => !p.product.startsWith('pass_')).map(p => p.product);

    res.json({ hasPremium, premiumExpiry, unlockedItems, purchases: active });
  } catch(e) {
    console.error('Purchases API error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── CLAIM SEASON REWARDS (validation server-side) ──
//
// Le client appelle cet endpoint à la fin d'une saison.
// Le serveur calcule lui-même le rang du joueur depuis l'ELO réel en BDD,
// et débloque uniquement les items correspondants.
//
const SEASON_DURATION_MS = 45 * 24 * 3600 * 1000;
const SEASON_START_EPOCH = new Date('2026-04-01T00:00:00Z').getTime();
function getServerSeasonNumber() {
  return Math.floor((Date.now() - SEASON_START_EPOCH) / SEASON_DURATION_MS) + 1;
}
function getRankFromElo(elo) {
  const e = elo | 0;
  if (e >= 5000) return 'Champion';
  if (e >= 4000) return 'Diamant';
  if (e >= 3000) return 'Platine';
  if (e >= 2000) return 'Or';
  if (e >= 1000) return 'Argent';
  return 'Bronze';
}
const RANK_ORDER = ['Bronze','Argent','Or','Platine','Diamant','Champion'];
function getSeasonRewardItems(rankName, seasonNum) {
  const s = 'S' + seasonNum;
  // Mêmes IDs que dans le client (getSeasonRewards)
  const ALL = {
    Bronze:   [{type:'border', id:'border_bronze_'+s}],
    Argent:   [{type:'border', id:'border_argent_'+s}, {type:'title', id:'combattant_'+s}],
    Or:       [{type:'border', id:'border_or_'+s}, {type:'title', id:'combattant_'+s}, {type:'emote', id:'emote_ranked_'+s}],
    Platine:  [{type:'border', id:'border_platine_'+s}, {type:'title', id:'combattant_'+s}, {type:'emote', id:'emote_ranked_'+s}, {type:'avatar', id:'avatar_ranked_'+s}],
    Diamant:  [{type:'border', id:'border_diamant_'+s}, {type:'title', id:'combattant_'+s}, {type:'emote', id:'emote_ranked_'+s}, {type:'avatar', id:'avatar_ranked_'+s}, {type:'avatar', id:'avatar_legend_'+s}],
    Champion: [{type:'border', id:'border_champion_'+s}, {type:'title', id:'legende_'+s}, {type:'emote', id:'emote_ranked_'+s}, {type:'avatar', id:'avatar_ranked_'+s}, {type:'avatar', id:'avatar_legend_'+s}, {type:'music', id:'music_consecration_'+s}]
  };
  // Cumulatif : tous les rangs jusqu'au sien
  const idx = RANK_ORDER.indexOf(rankName);
  if (idx < 0) return [];
  const items = [];
  for (let i = 0; i <= idx; i++) items.push(...(ALL[RANK_ORDER[i]] || []));
  return items;
}

app.post('/api/profile/claim-season-rewards', httpRateLimit(10), async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'auth_required' }); return;
    }
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authErr } = await supa.auth.getUser(token);
    if (authErr || !user) { res.status(403).json({ error: 'unauthorized' }); return; }

    const seasonNumberClaimed = parseInt(req.body?.seasonNumber, 10);
    const currentSeasonNumber = getServerSeasonNumber();
    if (!seasonNumberClaimed || seasonNumberClaimed >= currentSeasonNumber) {
      res.status(400).json({ error: 'invalid_season', currentSeason: currentSeasonNumber }); return;
    }

    // Lit le profil pour calculer le vrai rang
    const { data: prof, error: e1 } = await supaAdmin.from('profiles')
      .select('elo_solo, unlocked_cosmetics, title')
      .eq('id', user.id).single();
    if (e1 || !prof) { res.status(404).json({ error: 'profile_not_found' }); return; }

    const elo = prof.elo_solo | 0;
    const rankName = getRankFromElo(elo);
    const items = getSeasonRewardItems(rankName, seasonNumberClaimed);

    let unlocked = Array.isArray(prof.unlocked_cosmetics) ? [...prof.unlocked_cosmetics] : [];
    let titleToSet = prof.title || null;
    items.forEach(it => {
      if (it.type === 'title') titleToSet = it.id; // last title = rang max
      if (it.id && !unlocked.includes(it.id)) unlocked.push(it.id);
    });

    const update = { unlocked_cosmetics: unlocked };
    if (titleToSet) update.title = titleToSet;

    const { error: e2 } = await supaAdmin.from('profiles').update(update).eq('id', user.id);
    if (e2) { res.status(500).json({ error: e2.message }); return; }

    res.json({ ok: true, rank: rankName, items_unlocked: items.map(i => i.id), unlocked_cosmetics: unlocked, title: titleToSet });
  } catch(e) {
    console.error('claim-season-rewards error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── CLAIM LEVEL REWARDS (validation server-side) ──
// Lit le XP/niveau réel et débloque les rewards correspondants.
app.post('/api/profile/claim-level-rewards', httpRateLimit(60), async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'auth_required' }); return;
    }
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authErr } = await supa.auth.getUser(token);
    if (authErr || !user) { res.status(403).json({ error: 'unauthorized' }); return; }

    const { data: prof, error: e1 } = await supaAdmin.from('profiles')
      .select('xp, level, unlocked_cosmetics')
      .eq('id', user.id).single();
    if (e1 || !prof) { res.status(404).json({ error: 'profile_not_found' }); return; }

    const newRewardIds = Array.isArray(req.body?.newRewardIds) ? req.body.newRewardIds : null;
    if (!newRewardIds || newRewardIds.length === 0) {
      res.status(400).json({ error: 'no_rewards_specified' }); return;
    }

    // Sécurité minimale : limite à 50 items par claim
    const safeRewards = newRewardIds.slice(0, 50).filter(r => typeof r === 'string' && r.length < 80);

    let unlocked = Array.isArray(prof.unlocked_cosmetics) ? [...prof.unlocked_cosmetics] : [];
    const added = [];
    safeRewards.forEach(r => {
      if (!unlocked.includes(r)) { unlocked.push(r); added.push(r); }
    });

    if (added.length === 0) {
      res.json({ ok: true, added: [], unlocked_cosmetics: unlocked }); return;
    }

    const { error: e2 } = await supaAdmin.from('profiles')
      .update({ unlocked_cosmetics: unlocked }).eq('id', user.id);
    if (e2) { res.status(500).json({ error: e2.message }); return; }

    res.json({ ok: true, added, unlocked_cosmetics: unlocked });
  } catch(e) {
    console.error('claim-level-rewards error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── MIND PASS XP (validation server-side du daily cap) ──
//
// Le client appelle cet endpoint quand un joueur gagne du XP en jeu.
// Le serveur vérifie le daily cap, débite, et renvoie le nouveau total + level.
// pass_daily_xp en BDD : JSONB { "YYYY-MM-DD": xp_credited_today }
//
// 50 niveaux × 1000 XP = 50 000 XP à gagner en 30 jours → ~1700/jour
const PASS_DAILY_CAP = 1700;
const PASS_XP_PER_LEVEL = 1000;
const PASS_TOTAL_LEVELS = 50;

app.post('/api/profile/credit-pass-xp', httpRateLimit(120), async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'auth_required' }); return;
    }
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authErr } = await supa.auth.getUser(token);
    if (authErr || !user) { res.status(403).json({ error: 'unauthorized' }); return; }

    const amount = parseInt(req.body?.amount, 10);
    if (!Number.isFinite(amount) || amount <= 0 || amount > 5000) {
      res.status(400).json({ error: 'invalid_amount' }); return;
    }

    // Lit le profil actuel
    const { data: prof, error: e1 } = await supaAdmin.from('profiles')
      .select('pass_xp_total, pass_daily_xp')
      .eq('id', user.id).single();
    if (e1 || !prof) { res.status(404).json({ error: 'profile_not_found' }); return; }

    const today = new Date().toISOString().slice(0, 10);
    const dailyMap = (prof.pass_daily_xp && typeof prof.pass_daily_xp === 'object') ? prof.pass_daily_xp : {};
    const usedToday = parseInt(dailyMap[today], 10) || 0;
    const remaining = Math.max(0, PASS_DAILY_CAP - usedToday);
    const credited = Math.min(amount, remaining);

    if (credited <= 0) {
      const oldXP = prof.pass_xp_total | 0;
      res.json({
        credited: 0, capped: true,
        xp_total: oldXP,
        level: Math.min(Math.floor(oldXP / PASS_XP_PER_LEVEL), PASS_TOTAL_LEVELS),
        daily_used: usedToday,
        daily_cap: PASS_DAILY_CAP
      });
      return;
    }

    const newTotal = (prof.pass_xp_total | 0) + credited;
    // Garde uniquement les 7 derniers jours dans la map (cleanup auto)
    const cleanedDaily = {};
    const cutoff = Date.now() - 7 * 24 * 3600 * 1000;
    for (const [k, v] of Object.entries(dailyMap)) {
      if (new Date(k).getTime() >= cutoff) cleanedDaily[k] = v;
    }
    cleanedDaily[today] = usedToday + credited;

    const { error: e2 } = await supaAdmin.from('profiles')
      .update({ pass_xp_total: newTotal, pass_daily_xp: cleanedDaily })
      .eq('id', user.id);
    if (e2) { res.status(500).json({ error: e2.message }); return; }

    const newLevel = Math.min(Math.floor(newTotal / PASS_XP_PER_LEVEL), PASS_TOTAL_LEVELS);
    const oldLevel = Math.min(Math.floor((prof.pass_xp_total | 0) / PASS_XP_PER_LEVEL), PASS_TOTAL_LEVELS);

    res.json({
      credited,
      capped: credited < amount,
      xp_total: newTotal,
      level: newLevel,
      level_up: newLevel > oldLevel,
      old_level: oldLevel,
      daily_used: usedToday + credited,
      daily_cap: PASS_DAILY_CAP
    });
  } catch(e) {
    console.error('credit-pass-xp error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── CHECK ANSWER (validation server-side pour modes solo/survie/infini) ──
//
// Le client envoie l'ID de la question + sa réponse, le serveur consulte la BDD
// pour la vraie bonne réponse, et renvoie correct: true/false + l'index correct.
// Anti-retry : un user ne peut répondre qu'1 fois par question (Map TTL 1h).
//
const answerSessions = new Map(); // userId+qid → { answered: true, correct, correctIndex, expires }

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of answerSessions) if (v.expires < now) answerSessions.delete(k);
}, 600000); // cleanup toutes les 10 min

// Cache in-memory pour /api/check-answer
// → Élimine les appels Supabase répétitifs sur les questions populaires + l'auth getUser
const questionAnswerCache = new Map(); // questionId → { correctIndex, answers, expires }
const authTokenCache = new Map();      // token → { userId, expires }
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of questionAnswerCache) if (v.expires < now) questionAnswerCache.delete(k);
  for (const [k, v] of authTokenCache)      if (v.expires < now) authTokenCache.delete(k);
}, 600000); // cleanup toutes les 10 min

app.post('/api/check-answer', httpRateLimit(120), async (req, res) => {
  try {
    // Auth optionnelle : on cache le résultat (évite appel auth.getUser à chaque fois)
    let userId = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.replace('Bearer ', '');
      const cached = authTokenCache.get(token);
      if (cached && cached.expires > Date.now()) {
        userId = cached.userId;
      } else {
        const { data: { user } } = await supa.auth.getUser(token);
        if (user) {
          userId = user.id;
          authTokenCache.set(token, { userId, expires: Date.now() + 1800000 }); // 30 min
        }
      }
    }

    const { questionId, userAnswer } = req.body || {};
    if (!questionId || typeof questionId !== 'string') {
      res.status(400).json({ error: 'invalid_question_id' }); return;
    }

    // Anti-retry : seulement si authentifié
    if (userId) {
      const sessionKey = userId + ':' + questionId;
      const existing = answerSessions.get(sessionKey);
      if (existing) {
        res.json({ correct: existing.correct, correctIndex: existing.correctIndex, alreadyAnswered: true });
        return;
      }
    }

    // Lookup question — d'abord en cache, puis Supabase si miss
    let correctIndex, answers;
    const qCached = questionAnswerCache.get(questionId);
    if (qCached && qCached.expires > Date.now()) {
      correctIndex = qCached.correctIndex;
      answers = qCached.answers;
    } else {
      const { data: q, error: qErr } = await supa.from('translated_questions')
        .select('correct_index, answers_fr').eq('id', questionId).single();
      if (qErr || !q) { res.status(404).json({ error: 'question_not_found' }); return; }
      answers = q.answers_fr;
      if (typeof answers === 'string') { try { answers = JSON.parse(answers); } catch(e) {} }
      if (!Array.isArray(answers)) { res.status(500).json({ error: 'bad_question_data' }); return; }
      correctIndex = q.correct_index;
      questionAnswerCache.set(questionId, {
        correctIndex, answers,
        expires: Date.now() + 3600000 // 1h
      });
    }
    let correct = false;

    if (typeof userAnswer === 'number') {
      correct = (userAnswer === correctIndex);
    } else if (typeof userAnswer === 'string') {
      // Open answer : compare normalizée à la bonne réponse
      correct = isOpenAnswerCorrect(userAnswer, answers[correctIndex] || '');
    } else {
      res.status(400).json({ error: 'invalid_user_answer' }); return;
    }

    // Stocke pour anti-retry (uniquement si auth)
    if (userId) {
      answerSessions.set(userId + ':' + questionId, {
        answered: true, correct, correctIndex,
        expires: Date.now() + 3600000 // 1h
      });
    }

    res.json({ correct, correctIndex });
  } catch(e) {
    console.error('check-answer error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── REPORT QUESTION (signalement par les joueurs) ──
const REPORT_REASONS = ['wrong_answer','bad_question','offensive','typo','other'];
app.post('/api/report-question', httpRateLimit(20), async (req, res) => {
  try {
    const { questionId, reason, comment } = req.body || {};
    if (!questionId || typeof questionId !== 'string') {
      res.status(400).json({ error: 'invalid_question_id' }); return;
    }
    if (!REPORT_REASONS.includes(reason)) {
      res.status(400).json({ error: 'invalid_reason' }); return;
    }
    const cleanComment = typeof comment === 'string' ? comment.slice(0, 500) : null;

    // userId optionnel (anonyme accepté)
    let userId = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.replace('Bearer ', '');
      const { data: { user } } = await supa.auth.getUser(token);
      if (user) userId = user.id;
    }

    const { error } = await supa.from('question_reports').insert({
      question_id: questionId,
      user_id: userId,
      reason,
      comment: cleanComment
    });
    if (error) {
      console.error('Report insert error:', error.message);
      res.status(500).json({ error: 'db_error' }); return;
    }
    res.json({ ok: true });
  } catch(e) {
    console.error('Report endpoint error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// ── ADMIN : liste des questions signalées ──
app.get('/api/admin/reports', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'auth_required' }); return;
    }
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supa.auth.getUser(token);
    if (error || !user) { res.status(403).json({ error: 'unauthorized' }); return; }
    const ADMIN_USER_IDS = (process.env.ADMIN_USER_IDS || '').split(',').filter(Boolean);
    if (!ADMIN_USER_IDS.includes(user.id)) { res.status(403).json({ error: 'admin_only' }); return; }

    // Utilise supaAdmin (service_role) pour bypass RLS — admin a le droit de tout voir
    const { data, error: e2 } = await supaAdmin.from('question_reports')
      .select('id, question_id, reason, comment, status, created_at, translated_questions(question_fr, answers_fr, correct_index, category)')
      .order('created_at', { ascending: false })
      .limit(500);
    if (e2) { res.status(500).json({ error: e2.message }); return; }
    res.json({ reports: data || [] });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── VALIDATE PSEUDO (modération à la création/changement) ──
app.post('/api/validate-pseudo', httpRateLimit(20), async (req, res) => {
  try {
    const { pseudo } = req.body || {};
    if (!pseudo || typeof pseudo !== 'string') {
      res.status(400).json({ ok: false, reason: 'invalid_input' }); return;
    }
    if (!moderation) {
      res.json({ ok: true, source: 'no_moderation' }); return;
    }
    const verdict = await moderation.moderatePseudo(pseudo);
    res.json(verdict);
  } catch(e) {
    console.error('Pseudo validation error:', e.message);
    res.status(500).json({ ok: false, reason: 'server_error' });
  }
});

// ── ADMIN : récupère les comptes flaggués pour triche (auth requise) ──
app.get('/api/admin/cheat-flagged', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Authentication required' }); return;
    }
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supa.auth.getUser(token);
    if (error || !user) { res.status(403).json({ error: 'Unauthorized' }); return; }

    // TODO : remplacer par une vraie vérification admin (table admins ou rôle Supabase)
    const ADMIN_USER_IDS = (process.env.ADMIN_USER_IDS || '').split(',').filter(Boolean);
    if (!ADMIN_USER_IDS.includes(user.id)) {
      res.status(403).json({ error: 'Admin only' }); return;
    }

    if (!cheatDetection) { res.json({ flagged: [], summary: null }); return; }
    res.json({
      flagged: cheatDetection.getFlaggedUsers(50),
      summary: cheatDetection.getStatsSummary()
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── STRIPE PRODUCTS ──
const STRIPE_PRODUCTS = {
  // Mind Pass : achat unique, valable 30 jours (1 saison)
  pass_monthly:           { name: 'Mind Impact Pass — 30 jours', price: 299,  mode: 'payment' },
  // Avatars exclusifs boutique
  avatar_shadow_samurai:  { name: 'Avatar Samouraï des Ombres',  price: 99,   mode: 'payment' },
  avatar_twilight_assassin:{ name: 'Avatar Assassin du Crépuscule', price: 99, mode: 'payment' },
  avatar_anubis:          { name: 'Avatar Anubis',               price: 99,   mode: 'payment' },
  avatar_fenrir:          { name: 'Avatar Fenrir',               price: 99,   mode: 'payment' },
  // Musiques exclusives boutique
  music_new_world:        { name: 'Musique Nouveau Monde',       price: 99,   mode: 'payment' },
  music_celebration:      { name: 'Musique Célébration',         price: 99,   mode: 'payment' },
  no_ads:                 { name: 'Sans Publicité (à vie)',      price: 299,  mode: 'payment' },
};

// ── STRIPE CHECKOUT ──
app.post('/create-checkout-session', httpRateLimit(10), async (req, res) => {
  if (!stripe) { res.status(500).json({ error: 'Stripe not configured' }); return; }
  try {
    const { product, userId, username, successUrl, cancelUrl } = req.body;
    const prod = STRIPE_PRODUCTS[product];
    if (!prod) { res.status(400).json({ error: 'Product not found' }); return; }

    // Validate redirect URLs (prevent open redirect)
    const allowedDomains = ['mindimpact.online', 'brainbattle-client.vercel.app', 'localhost'];
    const isValidUrl = (url) => { try { const u = new URL(url); return allowedDomains.some(d => u.hostname.includes(d)); } catch { return false; } };
    if (!isValidUrl(successUrl) || !isValidUrl(cancelUrl)) { res.status(400).json({ error: 'Invalid redirect URL' }); return; }

    const sessionConfig = {
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: { name: prod.name, metadata: { userId, username } },
          unit_amount: prod.price,
          ...(prod.mode === 'subscription' ? { recurring: { interval: prod.interval } } : {}),
        },
        quantity: 1,
      }],
      mode: prod.mode === 'subscription' ? 'subscription' : 'payment',
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: { userId, username, product },
    };

    const session = await stripe.checkout.sessions.create(sessionConfig);
    res.json({ sessionId: session.id, url: session.url });
    console.log('💳 Checkout session créée:', product, 'pour', username);
  } catch(e) {
    console.error('Stripe error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════
//  UTILITAIRES
// ══════════════════════════════════════════
function normalizeAnswer(s) {
  return (s || '').toString().toLowerCase().trim()
    .replace(/œ/g,'oe').replace(/æ/g,'ae').replace(/ø/g,'o').replace(/ß/g,'ss')
    .normalize('NFD').replace(/[\u0300-\u036f]/g,'')
    .replace(/[^\p{L}\p{N}\s]/gu,'')
    .replace(/\s+/g,' ').trim();
}
function isOpenAnswerCorrect(input, expected) {
  const a = normalizeAnswer(input);
  const b = normalizeAnswer(expected);
  if (!a || !b) return false;
  if (a === b) return true;
  if (b.split(' | ').some(x => x.trim() === a)) return true;
  return false;
}

function genCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// ══════════════════════════════════════════
//  STATE
// ══════════════════════════════════════════
const rooms   = {};  // code → room
const players = {};  // socketId → { code, name, avatar }

// Structure d'une room :
// {
//   code, host, status: 'waiting'|'playing'|'results',
//   mode: 'friends'|'royale'|'team'|'chrono',
//   players: { socketId: { name, avatar, score, lives, alive, answers:[] } },
//   questions: [], currentQ: 0, category: '0', difficulty: '',
//   timer: null, maxQ: 10
// }

// ══════════════════════════════════════════
//  FETCH QUESTIONS — Supabase FR (priorité) + OpenTDB EN (fallback)
// ══════════════════════════════════════════
async function fetchQuestions(nb, category, difficulty) {
  nb = Math.max(1, Math.min(50, parseInt(nb) || 10));

  // ── Tentative 1 : Supabase FR ──
  try {
    const catName = (category && category !== '0') ? (CAT_MAP[String(category)] || category) : null;
    const diffValue = (difficulty && ['easy','medium','hard'].includes(difficulty)) ? difficulty : null;

    // Appel RPC avec vrai ORDER BY random() côté PostgreSQL
    const { data, error } = await supa.rpc('get_random_questions', {
      cat_filter: catName,
      diff_filter: diffValue,
      num_questions: nb
    });

    if (error) console.warn('RPC get_random_questions error:', error.message);
    if (!error && data && data.length >= nb) {
      return data.slice(0, nb).map(q => {
        // answers_fr peut être un string JSON ou un array selon le type de colonne
        let answers = q.answers_fr;
        if (typeof answers === 'string') { try { answers = JSON.parse(answers); } catch(e) {} }
        return { id: q.id, cat: q.category || 'Culture générale', q: q.question_fr.trim(), answers, correct: q.correct_index };
      });
    }

    // Fallback sans filtres
    const { data: d2 } = await supa.rpc('get_random_questions', {
      cat_filter: null, diff_filter: null, num_questions: nb
    });
    if (d2 && d2.length >= nb) {
      return d2.slice(0, nb).map(q => {
        let answers = q.answers_fr;
        if (typeof answers === 'string') { try { answers = JSON.parse(answers); } catch(e) {} }
        return { id: q.id, cat: q.category || 'Culture générale', q: q.question_fr.trim(), answers, correct: q.correct_index };
      });
    }
  } catch(e) {
    console.warn('Supabase fetch error, falling back to OpenTDB:', e.message);
  }

  // ── Fallback : OpenTDB EN ──
  let url = `https://opentdb.com/api.php?amount=${nb}&type=multiple`;
  if (category && category !== '0') url += `&category=${encodeURIComponent(category)}`;
  if (difficulty && ['easy','medium','hard'].includes(difficulty)) url += `&difficulty=${difficulty}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const res  = await fetch(url, { signal: controller.signal });
    const data = await res.json();
    if (data.response_code !== 0) throw new Error('Pas assez de questions.');
    return data.results.map(q => {
      const answers = shuffle([...q.incorrect_answers, q.correct_answer]);
      return {
        cat:     decodeHTMLEntities(q.category),
        q:       decodeHTMLEntities(q.question),
        answers: answers.map(a => decodeHTMLEntities(a)),
        correct: answers.indexOf(q.correct_answer)
      };
    });
  } finally {
    clearTimeout(timeout);
  }
}

function decodeHTMLEntities(str) {
  return str
    .replace(/&amp;/g,  '&')
    .replace(/&lt;/g,   '<')
    .replace(/&gt;/g,   '>')
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/&ldquo;/g,'"')
    .replace(/&rdquo;/g,'"')
    .replace(/&laquo;/g,'«')
    .replace(/&raquo;/g,'»');
}

// ══════════════════════════════════════════
//  SOCKET.IO
// ══════════════════════════════════════════
// ── SOCKET RATE LIMITING ──
const socketRateLimits = {};
function rateLimitSocket(socketId, event, maxPerMinute = 30) {
  const key = socketId + ':' + event;
  const now = Date.now();
  if (!socketRateLimits[key]) socketRateLimits[key] = [];
  socketRateLimits[key] = socketRateLimits[key].filter(t => now - t < 60000);
  if (socketRateLimits[key].length >= maxPerMinute) return false;
  socketRateLimits[key].push(now);
  return true;
}
// Clean up rate limit data every 5 minutes
setInterval(() => { Object.keys(socketRateLimits).forEach(k => { if (!socketRateLimits[k].length) delete socketRateLimits[k]; }); }, 300000);

io.on('connection', (socket) => {
  console.log(`✅ Connecté: ${socket.id}`);

  // ── CRÉER UN SALON ──
  socket.on('create_room', ({ name, avatar, mode, category, difficulty, maxQ }) => {
    if (!rateLimitSocket(socket.id, 'create_room', 5)) return;
    if (typeof name !== 'string' || name.length > 30) return;
    if (avatar && (typeof avatar !== 'string' || avatar.length > 50)) return;
    const code = genCode();
    rooms[code] = {
      code, host: socket.id,
      status: 'waiting', mode: mode || 'friends',
      category: category || '0', difficulty: difficulty || '',
      maxQ: maxQ || 10,
      players: {},
      questions: [], currentQ: 0, timer: null,
      answers: {}, answerCount: 0
    };
    rooms[code].players[socket.id] = {
      name, avatar: avatar || '🎮',
      score: 0, lives: 3, alive: true, answers: []
    };
    players[socket.id] = { code, name, avatar };
    socket.join(code);
    socket.emit('room_created', { code, room: sanitizeRoom(rooms[code]) });
    console.log(`🏠 Salon créé: ${code} par ${name} (${mode})`);
  });

  // ── REJOINDRE UN SALON ──
  socket.on('join_room', ({ code, name, avatar }) => {
    if (!rateLimitSocket(socket.id, 'join_room', 10)) return;
    if (typeof name !== 'string' || name.length > 30) return;
    if (avatar && (typeof avatar !== 'string' || avatar.length > 50)) return;
    const room = rooms[code];
    if (!room) { socket.emit('error', { msg: 'Salon introuvable. Vérifie le code.' }); return; }
    if (room.status !== 'waiting') { socket.emit('error', { msg: 'La partie a déjà commencé.' }); return; }
    if (Object.keys(room.players).length >= 8) { socket.emit('error', { msg: 'Salon complet (8 joueurs max).' }); return; }

    room.players[socket.id] = {
      name, avatar: avatar || '🎮',
      score: 0, lives: 3, alive: true, answers: []
    };
    players[socket.id] = { code, name, avatar };
    socket.join(code);
    socket.emit('room_joined', { code, room: sanitizeRoom(room) });
    io.to(code).emit('player_joined', { room: sanitizeRoom(room) });
    console.log(`👤 ${name} a rejoint ${code}`);
  });

  // ── LANCER LA PARTIE (hôte seulement) ──
  socket.on('start_game', async ({ code }) => {
    const room = rooms[code];
    if (!room || room.host !== socket.id) return;
    if (Object.keys(room.players).length < 2) {
      socket.emit('error', { msg: 'Il faut au moins 2 joueurs pour commencer.' }); return;
    }
    try {
      room.questions = await fetchQuestions(room.maxQ, room.category, room.difficulty);
    } catch(e) {
      socket.emit('error', { msg: 'Erreur chargement des questions. Réessaie.' }); return;
    }
    room.status   = 'playing';
    room.currentQ = 0;
    // Init lives for battle royale
    if (room.mode === 'royale') {
      Object.values(room.players).forEach(p => { p.lives = 3; p.alive = true; });
    }
    // Assign teams for team mode
    if (room.mode === 'team') {
      const pids = Object.keys(room.players);
      pids.forEach((pid, i) => {
        room.players[pid].team = i % 2 === 0 ? 'A' : 'B';
        room.players[pid].alive = true;
      });
      room.teamScores = { A: 0, B: 0 };
    }
    // Init chrono mode — 2 minutes, unlimited questions, combo system
    if (room.mode === 'chrono') {
      Object.values(room.players).forEach(p => {
        p.alive      = true;
        p.chronoScore = 0;
        p.combo       = 0;
        p.answered    = 0;
        p.correct     = 0;
      });
      room.chronoStartTime = Date.now();
      room.chronoDuration  = 120000; // 2 minutes
      room.chronoQuestions = []; // infinite pool
      room.chronoPlayerQ   = {}; // per-player question index
      Object.keys(room.players).forEach(pid => { room.chronoPlayerQ[pid] = 0; });
    }
    io.to(code).emit('game_started', { room: sanitizeRoom(room) });
    if (room.mode === 'tactical') {
      initTacticalRoom(code, room.players, room.questions);
      setTimeout(() => startTacticalRound(code, io), 1500);
    } else if (room.mode === 'chrono') {
      setTimeout(() => startChronoMode(code, io), 1000);
    } else {
      setTimeout(() => sendQuestion(code), 1000);
    }
    console.log(`🎮 Partie lancée: ${code}`);
  });

  // ── RÉPONDRE ──
  socket.on('answer', ({ code, questionIndex, answerIndex, timeLeft, openAnswer }) => {
    const room = rooms[code];
    if (!room || room.status !== 'playing') return;
    if (room.currentQ !== questionIndex) return;
    const player = room.players[socket.id];
    if (!player || !player.alive) return;
    // Prevent double answer
    if (room.answers[socket.id] !== undefined) return;

    const q       = room.questions[questionIndex];
    let correct   = false;
    let finalIdx  = answerIndex;
    // Open answer validation (server-side to prevent cheating)
    if (typeof openAnswer === 'string' && q.answers && q.answers.length === 1) {
      correct = isOpenAnswerCorrect(openAnswer, q.answers[q.correct]);
      finalIdx = correct ? q.correct : -1;
    } else {
      correct = answerIndex === q.correct;
    }
    // Durée selon config host (5-60s, défaut 20s)
    const dur     = (room.timer_sec && room.timer_sec >= 5 && room.timer_sec <= 60) ? room.timer_sec : 20;
    // Server-side time validation: cap timeLeft to prevent cheating
    const safeTimeLeft = Math.max(0, Math.min(dur, typeof timeLeft === 'number' ? timeLeft : 0));
    const pts     = correct ? Math.round(100 + (safeTimeLeft / dur) * 100) : 0;

    room.answers[socket.id] = { answerIndex: finalIdx, correct, pts, timeLeft, openAnswer };
    if (correct) player.score += pts;

    // Hook détection de triche
    if (cheatDetection && socket.userId) {
      const responseMs = Math.max(0, (20 - safeTimeLeft) * 1000);
      cheatDetection.recordAnswer(socket.userId, correct, responseMs, room.difficulty || 'medium');
    }

    // Team mode: add points to team score
    if (room.mode === 'team') {
      const team = player.team;
      if (correct && team) room.teamScores[team] = (room.teamScores[team]||0) + pts;
    }
    // Chrono: score based on correctness + combo
    if (room.mode === 'chrono') {
      player.answered = (player.answered || 0) + 1;
      if (correct) {
        player.combo = (player.combo || 0) + 1;
        player.correct = (player.correct || 0) + 1;
        let comboBonus = 0;
        if (player.combo >= 10) comboBonus = 100;
        else if (player.combo >= 5) comboBonus = 50;
        else if (player.combo >= 2) comboBonus = 25;
        const chronoPts = 100 + comboBonus;
        player.chronoScore = (player.chronoScore || 0) + chronoPts;
        player.score = player.chronoScore;
        socket.emit('chrono_result', { correct: true, combo: player.combo, points: chronoPts, score: player.chronoScore });
      } else {
        player.combo = 0;
        socket.emit('chrono_result', { correct: false, combo: 0, points: 0, score: player.chronoScore || 0 });
      }
      sendChronoQuestion(code, socket.id, io);
      const scores = Object.entries(room.players).map(([id, p]) => ({ id, name: p.name, avatar: p.avatar, score: p.chronoScore || 0, combo: p.combo || 0 })).sort((a,b) => b.score - a.score);
      io.to(code).emit('chrono_scores_update', { scores });
      return;
    }
    // Battle royale: lose a life on wrong answer
    if (room.mode === 'royale' && !correct) {
      player.lives--;
      if (player.lives <= 0) {
        player.alive = false;
        io.to(code).emit('player_eliminated', { name: player.name });
      }
    }

    // Notify everyone of this answer (without revealing correct)
    io.to(code).emit('player_answered', {
      playerId: socket.id, name: player.name,
      correct, pts, score: player.score,
      lives: player.lives, alive: player.alive,
      team: player.team,
      teamScores: room.teamScores || null
    });

    room.answerCount++;
    const alivePlayers = Object.entries(room.players).filter(([,p]) => p.alive);

    // If all alive players answered → next question
    if (room.answerCount >= alivePlayers.length) {
      clearTimeout(room.timer);
      setTimeout(() => nextQuestion(code), 2000);
    }

    // Battle royale: check if only 1 left
    const stillAlive = alivePlayers.length;
    if (room.mode === 'royale' && stillAlive <= 1) {
      clearTimeout(room.timer);
      setTimeout(() => endGame(code), 2000);
    }
  });

  // ── DÉCONNEXION ──
  // ── FRIENDS & ONLINE STATUS ──
  socket.on('user_online', async ({ userId, username, token }) => {
    // Sécu : on n'enregistre socket.userId QUE si le token est valide.
    // Sans ça, n'importe qui pouvait se faire passer pour un autre userId
    // dans les events qui ne checkent pas socket.verified.
    if (!token || !userId) {
      socket.verified = false;
      return; // pas de token → on ne broadcast rien et on ne stocke pas userId
    }
    try {
      const { data: { user }, error } = await supa.auth.getUser(token);
      if (error || !user || user.id !== userId) {
        socket.verified = false;
        return;
      }
      socket.userId = userId;
      socket.username = username;
      socket.verified = true;
      socket.broadcast.emit('friend_online', { userId });
    } catch(e) {
      socket.verified = false;
    }
  });

  socket.on('friend_request', ({ toUserId, fromUsername, fromAvatar }) => {
    if (!socket.verified) return; // Must be verified to send friend requests
    if (!rateLimitSocket(socket.id, 'friend_request', 10)) return;
    for (const [id, s] of io.sockets.sockets) {
      if (s.userId === toUserId) {
        s.emit('friend_request_received', { fromUsername, fromAvatar });
        break;
      }
    }
  });

  socket.on('friend_accepted', ({ toUserId, fromUsername }) => {
    if (!socket.verified) return; // Anti-usurpation
    for (const [id, s] of io.sockets.sockets) {
      if (s.userId === toUserId) {
        s.emit('friend_accepted_notification', { fromUsername });
        break;
      }
    }
  });

  socket.on('private_msg', async ({ toUserId, content, fromUsername, fromAvatar }) => {
    if (!socket.verified) return; // Anti-usurpation : exige token Supabase valide
    if (!rateLimitSocket(socket.id, 'private_msg', 15)) return;
    if (!content || typeof content !== 'string' || !content.trim() || content.length > 200) return;
    if (moderation) {
      const verdict = await moderation.moderateChatMessage(content);
      if (!verdict.ok) {
        socket.emit('private_msg_blocked', { reason: verdict.reason });
        return;
      }
    }
    for (const [id, s] of io.sockets.sockets) {
      if (s.userId === toUserId) {
        s.emit('private_msg_received', { content, fromUsername, fromAvatar, fromUserId: socket.userId });
        break;
      }
    }
  });

  socket.on('game_invite', ({ toUserId, fromUsername, groupCode, mode }) => {
    if (!socket.verified) return; // Anti-usurpation
    if (!rateLimitSocket(socket.id, 'game_invite', 10)) return;
    for (const [id, s] of io.sockets.sockets) {
      if (s.userId === toUserId) {
        s.emit('game_invite_received', { fromUsername, groupCode, mode });
        break;
      }
    }
  });

  // Chat
  socket.on('chat_msg', async ({ code, msg }) => {
    if (!rateLimitSocket(socket.id, 'chat_msg', 20)) return;
    if (!msg || typeof msg !== 'string' || !msg.trim() || msg.length > 120) return;
    // Récupère le nom depuis l'état serveur (anti-spoof) ; ignore le name du client.
    const room = rooms[code];
    const trustedName = room?.players?.[socket.id]?.name;
    if (!trustedName) return; // pas dans la room → ignore
    if (moderation) {
      const verdict = await moderation.moderateChatMessage(msg);
      if (!verdict.ok) {
        socket.emit('chat_msg_blocked', { reason: verdict.reason });
        return;
      }
    }
    socket.to(code).emit('chat_msg', { name: trustedName, msg });
  });

  // Emotes
  socket.on('emote', ({ code, emote, name }) => {
    if (!rateLimitSocket(socket.id, 'emote', 10)) return;
    socket.to(code).emit('emote', { emote, name });
  });

  socket.on('disconnect', () => {
    if (socket.userId) socket.broadcast.emit('friend_offline', { userId: socket.userId });
    // Clean up matchmaking queues
    Object.keys(mmQueues).forEach(m => {
      const idx = mmQueues[m].findIndex(q => q.socketId === socket.id);
      if (idx !== -1) mmQueues[m].splice(idx, 1);
    });
    // Clean up team queue
    const tIdx = teamQueue.findIndex(q => q.socketId === socket.id);
    if (tIdx !== -1) teamQueue.splice(tIdx, 1);
    const pdata = players[socket.id];
    if (pdata) {
      const room = rooms[pdata.code];
      if (room) {
        delete room.players[socket.id];
        delete room.answers[socket.id];
        io.to(pdata.code).emit('player_left', {
          name: pdata.name, room: sanitizeRoom(room)
        });
        // Check if all remaining players have answered after disconnect
        if (room.status === 'playing') {
          const alivePlayers = Object.values(room.players).filter(p => p.alive !== false);
          const answeredCount = Object.keys(room.answers || {}).length;
          if (alivePlayers.length > 0 && answeredCount >= alivePlayers.length) {
            nextQuestion(pdata.code);
          }
        }
        // If host left and room not empty, assign new host
        if (room.host === socket.id) {
          const remaining = Object.keys(room.players);
          if (remaining.length > 0) {
            room.host = remaining[0];
            io.to(pdata.code).emit('new_host', { hostId: room.host });
          } else {
            clearTimeout(room.timer);
            delete rooms[pdata.code];
          }
        }
      }
      delete players[socket.id];
    }
    console.log(`❌ Déconnecté: ${socket.id}`);
  });

  // ── CHRONO ANSWER ──
  socket.on('chrono_answer', ({ code, answerIndex, openAnswer }) => {
    const room = rooms[code];
    if (!room || room.mode !== 'chrono' || room.status !== 'playing') return;
    const player = room.players[socket.id];
    if (!player) return;

    const elapsed = Date.now() - (room.chronoStartTime || Date.now());
    if (elapsed >= (room.chronoDuration || 120000)) return;

    // Server-side scoring using stored correct answer
    const correctIdx = room.chronoCurrentAnswers?.[socket.id];
    const expectedAnswer = room.chronoCurrentExpected?.[socket.id];
    let isCorrect = false;
    if (typeof openAnswer === 'string' && expectedAnswer) {
      isCorrect = isOpenAnswerCorrect(openAnswer, expectedAnswer);
    } else {
      isCorrect = (correctIdx !== undefined && answerIndex === correctIdx);
    }
    if (isCorrect) {
      player.combo = (player.combo || 0) + 1;
      const comboBonus = player.combo >= 10 ? 100 : player.combo >= 5 ? 50 : player.combo >= 2 ? 25 : 0;
      const pts = 50 + comboBonus;
      player.chronoScore = (player.chronoScore || 0) + pts;
      player.correct = (player.correct || 0) + 1;
    } else {
      player.combo = 0;
    }

    // Send result to player
    socket.emit('chrono_result', { correct: isCorrect, score: player.chronoScore || 0, combo: player.combo || 0, correctIndex: correctIdx });

    // Update scores for all
    const scores = Object.entries(room.players).map(([id, p]) => ({
      id, name: p.name, avatar: p.avatar, score: p.chronoScore || 0, combo: p.combo || 0
    })).sort((a,b) => b.score - a.score);
    io.to(code).emit('chrono_scores_update', { scores });

    // Send next question
    sendChronoQuestion(code, socket.id, io);
  });

  // ── HOST CONFIG ──
  socket.on('host_config', ({ code, mode, category, difficulty, maxQ, timer }) => {
    if (!rateLimitSocket(socket.id, 'host_config', 30)) return;
    const room = rooms[code];
    if (!room || room.host !== socket.id) return;
    const validModes = ['friends','royale','team','chrono','tactical'];
    const validDiffs = ['','easy','medium','hard'];
    if (mode && validModes.includes(mode))       room.mode       = mode;
    if (category)   room.category   = String(category).slice(0, 10);
    if (validDiffs.includes(difficulty)) room.difficulty = difficulty;
    if (maxQ) room.maxQ = Math.max(1, Math.min(50, parseInt(maxQ) || 10));
    if (timer) room.timer_sec = Math.max(5, Math.min(60, parseInt(timer) || 20));
    io.to(code).emit('host_config_updated', { mode: room.mode, category: room.category, difficulty: room.difficulty, maxQ: room.maxQ, timer: room.timer_sec });
    console.log(`⚙️ Config salon ${code}: mode=${room.mode} cat=${room.category} diff=${room.difficulty} nb=${room.maxQ} timer=${room.timer_sec}`);
  });

  // ── TACTICAL EVENTS ──
  registerTacticalEvents(socket, io);

  // ── VOTE CATÉGORIE (matchmaking) ──
  registerVoteCategoryHandler(socket, io);

  // ── MATCHMAKING ──
  socket.on('join_matchmaking', ({ mode, name, avatar, userId, groupCode, elo }) => {
    if (!rateLimitSocket(socket.id, 'join_matchmaking', 10)) return;
    if (typeof name !== 'string' || name.length > 30) return;
    if (avatar && (typeof avatar !== 'string' || avatar.length > 50)) return;
    const data = { socketId:socket.id, name, avatar, userId, groupCode, elo:elo||1, mode, joinedAt: Date.now() };
    Object.keys(mmQueues).forEach(m => {
      const idx = mmQueues[m].findIndex(q=>q.socketId===socket.id);
      if(idx!==-1) mmQueues[m].splice(idx,1);
    });
    if(!mmQueues[mode]) mmQueues[mode]=[];
    mmQueues[mode].push(data);
    if(groupCode){ if(!mmGroups[groupCode]) mmGroups[groupCode]=[]; mmGroups[groupCode].push(data); }
    console.log(`🔍 MM [${mode}]: ${name} (${mmQueues[mode].length} waiting)`);
    tryMatchmaking(mode, io);
  });

  socket.on('join_matchmade_room', ({ code }) => {
    const room = rooms[code];
    if(!room) return;
    if(!room.players[socket.id]) room.players[socket.id]={name:'Joueur',avatar:'🎮',score:0,lives:3,alive:true};
    players[socket.id]={code,name:room.players[socket.id].name};
    socket.join(code);
    io.to(code).emit('player_joined',{room:sanitizeRoom(room)});
  });

  // Pre-lobby group management
  socket.on('register_group', ({ groupCode, name, avatar, userId }) => {
    if (!mmGroups[groupCode]) mmGroups[groupCode] = [];
    mmGroups[groupCode] = mmGroups[groupCode].filter(p => p.socketId !== socket.id);
    mmGroups[groupCode].push({ socketId: socket.id, name, avatar, userId });
    socket.join('grp-' + groupCode);
    console.log(`👥 Groupe ${groupCode}: ${name} enregistré`);
  });

  socket.on('group_mode_change', ({ groupCode, mode }) => {
    socket.to('grp-' + groupCode).emit('mm_mode_changed', { mode });
    console.log(`🔄 Groupe ${groupCode}: mode → ${mode}`);
  });

  socket.on('leave_group', ({ groupCode }) => {
    if (groupCode && mmGroups[groupCode]) {
      mmGroups[groupCode] = mmGroups[groupCode].filter(p => p.socketId !== socket.id);
    }
    socket.leave('grp-' + groupCode);
  });

  socket.on('join_group', ({ groupCode, name, avatar, userId }) => {
    if (!mmGroups[groupCode]) { socket.emit('error', { msg: 'Groupe introuvable.' }); return; }
    mmGroups[groupCode].push({ socketId: socket.id, name, avatar, userId });
    socket.join('grp-' + groupCode);
    io.to('grp-' + groupCode).emit('mm_group_joined', { name, avatar });
    socket.emit('mm_group_joined', { name: 'toi', avatar });
    console.log(`👤 ${name} a rejoint le groupe ${groupCode}`);
  });

  socket.on('leave_matchmaking', ({ mode }) => {
    if(mode&&mmQueues[mode]){
      const idx=mmQueues[mode].findIndex(q=>q.socketId===socket.id);
      if(idx!==-1) mmQueues[mode].splice(idx,1);
    }
  });

  // ── TEAM RANKED MATCHMAKING ──
  socket.on('find_team_match', (data) => {
    const existing = teamQueue.findIndex(q => q.teamId === data.teamId);
    if (existing !== -1) teamQueue.splice(existing, 1);
    teamQueue.push({ socketId: socket.id, ...data });
    console.log(`🔍 Matchmaking: ${data.teamName} [ELO: ${data.elo}] - Queue: ${teamQueue.length}`);
    tryMatchTeams(io);
  });

  socket.on('cancel_team_match', () => {
    const idx = teamQueue.findIndex(q => q.socketId === socket.id);
    if (idx !== -1) { teamQueue.splice(idx, 1); console.log('❌ Matchmaking annulé'); }
  });
});

// ══════════════════════════════════════════
//  LOGIQUE DE JEU
// ══════════════════════════════════════════
function sendQuestion(code) {
  const room = rooms[code];
  if (!room) return;
  const q = room.questions[room.currentQ];
  room.answers    = {};
  room.answerCount = 0;

  // Send question without revealing correct answer
  io.to(code).emit('new_question', {
    index:   room.currentQ,
    total:   room.questions.length,
    cat:     q.cat,
    q:       q.q,
    qid:     q.id || null,
    answers: q.answers,
    players: sanitizePlayers(room.players)
  });

  // Auto-advance after 22 seconds (20s + 2s buffer)
  room.timer = setTimeout(() => {
    // Force anyone who hasn't answered
    Object.keys(room.players).forEach(sid => {
      if (room.players[sid].alive && room.answers[sid] === undefined) {
        room.answers[sid] = { answerIndex: -1, correct: false, pts: 0, timeLeft: 0 };
        if (room.mode === 'royale') {
          room.players[sid].lives--;
          if (room.players[sid].lives <= 0) {
            room.players[sid].alive = false;
            io.to(code).emit('player_eliminated', { name: room.players[sid].name });
          }
        }
      }
    });
    // Reveal correct answer
    io.to(code).emit('question_timeout', {
      correct: q.correct,
      players: sanitizePlayers(room.players)
    });
    setTimeout(() => nextQuestion(code), 2000);
  }, 22000);
}

function nextQuestion(code) {
  const room = rooms[code];
  if (!room) return;
  // Guard against double-call (timeout + all-answered race)
  if (room._advancing) return;
  room._advancing = true;
  setTimeout(() => { if (rooms[code]) rooms[code]._advancing = false; }, 500);

  // Reveal correct answer to all
  const q = room.questions[room.currentQ];
  io.to(code).emit('reveal_answer', {
    correct: q.correct,
    players: sanitizePlayers(room.players)
  });

  room.currentQ++;

  // Check battle royale — only 1 alive?
  const alive = Object.values(room.players).filter(p => p.alive).length;
  if (room.mode === 'royale' && alive <= 1) {
    setTimeout(() => endGame(code), 2500);
    return;
  }

  // All questions done?
  if (room.currentQ >= room.questions.length) {
    setTimeout(() => endGame(code), 2500);
    return;
  }

  setTimeout(() => sendQuestion(code), 3000);
}

function endGame(code) {
  const room = rooms[code];
  if (!room) return;
  room.status = 'results';
  clearTimeout(room.timer);

  let ranking = Object.entries(room.players)
    .map(([id, p]) => ({ id, name: p.name, avatar: p.avatar, score: p.score, alive: p.alive, team: p.team }))
    .sort((a, b) => b.score - a.score);

  // Team result
  let teamResult = null;
  if ((room.mode === 'team' || room.mode === 'team_ranked') && room.teamScores) {
    const winner = room.teamScores.A > room.teamScores.B ? 'A' : room.teamScores.B > room.teamScores.A ? 'B' : 'Égalité';
    teamResult = { scores: room.teamScores, winner };
    if (room.mode === 'team_ranked') {
      ranking.forEach(p => {
        const player = room.players[p.id];
        const playerTeam = player?.team;
        p.won = playerTeam === winner;
        p.eloChange = p.won ? ELO_TABLE[getRankName(p.elo||0)]?.win : ELO_TABLE[getRankName(p.elo||0)]?.loss;
      });
    }
  }

  // Chrono: rank by chrono score
  if (room.mode === 'chrono') {
    ranking = ranking
      .map(r => ({ ...r, score: room.players[r.id]?.chronoScore || 0 }))
      .sort((a, b) => b.score - a.score);
  }

  io.to(code).emit('game_over', { ranking, teamResult, mode: room.mode });
  console.log(`🏆 Partie terminée: ${code}`);

  // Clean up room after 5 min
  setTimeout(() => { delete rooms[code]; }, 300000);
}

// ══════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════
function sanitizeRoom(room) {
  return {
    code:       room.code,
    host:       room.host,
    status:     room.status,
    mode:       room.mode,
    category:   room.category,
    difficulty: room.difficulty,
    maxQ:       room.maxQ,
    currentQ:   room.currentQ,
    totalQ:     room.questions?.length || 0,
    players:    sanitizePlayers(room.players)
  };
}

function sanitizePlayers(players) {
  return Object.entries(players).reduce((acc, [id, p]) => {
    acc[id] = { name: p.name, avatar: p.avatar, score: p.score, lives: p.lives, alive: p.alive };
    return acc;
  }, {});
}

// ══════════════════════════════════════════
//  MATCHMAKING GÉNÉRAL
// ══════════════════════════════════════════

const mmQueues = { duel1v1:[], royale:[], team:[], tactical:[], chrono:[], ranked_solo:[], ranked_team:[], ranked_tactical:[] };
const mmGroups = {};

// Catégories disponibles pour le vote (toutes + option globale)
const VOTE_CATEGORIES = [
  { id:'0',   label:'🌍 Toutes catégories' },
  { id:'9',   label:'✨ Culture générale' },
  { id:'23',  label:'📖 Histoire' },
  { id:'22',  label:'🗺️ Géographie' },
  { id:'17',  label:'🔬 Science & Nature' },
  { id:'18',  label:'💻 Tech & Informatique' },
  { id:'19',  label:'🔢 Mathématiques' },
  { id:'21',  label:'🏆 Sport' },
  { id:'11',  label:'🎬 Cinéma' },
  { id:'14',  label:'📺 Séries TV' },
  { id:'15',  label:'🎮 Jeux vidéo' },
  { id:'12',  label:'🎵 Musique' },
  { id:'10',  label:'📚 Livres' },
  { id:'13',  label:'🎭 Comédies musicales' },
  { id:'16',  label:'🎲 Jeux de société' },
  { id:'20',  label:'⚡ Mythologie' },
  { id:'24',  label:'🏛️ Politique' },
  { id:'25',  label:'🎨 Art' },
  { id:'26',  label:'⭐ Célébrités' },
  { id:'27',  label:'🐾 Animaux' },
  { id:'28',  label:'🚗 Véhicules' },
  { id:'29',  label:'💥 Comics' },
  { id:'30',  label:'📱 Gadgets' },
  { id:'31',  label:'🇯🇵 Anime & Manga' },
  { id:'32',  label:'🎠 Dessins animés' },
  { id:'33',  label:'🍽️ Cuisine & Gastronomie' },
  { id:'34',  label:'🥖 Culture Française' },
  { id:'35',  label:'🧩 Logique & Énigmes' },
  { id:'36',  label:'🧙 Contes & Légendes' },
];


function tryMatchmaking(mode, io) {
  const queue = mmQueues[mode]||[];
  if(mode==='duel1v1'||mode==='ranked_solo'){ if(queue.length<2)return; createMatchmadeRoom(queue.splice(0,2),mode,io); }
  else if(mode==='royale'){
    // Launch with 8+ players, max 16. After 30s wait, launch with 4+
    if(queue.length>=16) createMatchmadeRoom(queue.splice(0,16),mode,io);
    else if(queue.length>=8) createMatchmadeRoom(queue.splice(0,Math.min(queue.length,16)),mode,io);
    else if(queue.length>=4){
      // Check if oldest player has waited 30s
      const oldest = queue[0];
      if(oldest && Date.now() - (oldest.joinedAt||Date.now()) > 30000){
        createMatchmadeRoom(queue.splice(0,Math.min(queue.length,16)),mode,io);
      }
    }
  }
  else if(mode==='team'){ if(queue.length>=4){ const c=Math.min(queue.length-(queue.length%2),8); createMatchmadeRoom(queue.splice(0,c),mode,io); } }
  else if(mode==='tactical'){ for(const s of [4,6,8]){ if(queue.length>=s){createMatchmadeRoom(queue.splice(0,s),mode,io);break;} } }
  else if(mode==='chrono'){ if(queue.length>=2) createMatchmadeRoom(queue.splice(0,Math.min(queue.length,6)),mode,io); }
}

async function createMatchmadeRoom(playerList, mode, io) {
  const code = genCode();
  rooms[code] = {
    code, host:playerList[0].socketId, status:'voting', mode,
    category:'0', difficulty:'', maxQ:10,
    players:{}, questions:[], currentQ:0, timer:null,
    answers:{}, answerCount:0, teamScores:{A:0,B:0},
    categoryVotes:{}, categoryVoteTimer:null
  };
  playerList.forEach((p,i) => {
    rooms[code].players[p.socketId]={name:p.name,avatar:p.avatar||'🎮',score:0,lives:3,alive:true,team:i<Math.ceil(playerList.length/2)?'A':'B'};
    players[p.socketId]={code,name:p.name};
    const s=io.sockets.sockets.get(p.socketId);
    if(s) s.join(code);
  });

  io.to(code).emit('mm_match_found',{roomCode:code,mode,players:playerList.map(p=>({name:p.name,avatar:p.avatar}))});
  console.log(`✅ Match [${mode}]: ${playerList.map(p=>p.name).join(' vs ')} → ${code}`);

  // ── Phase 1 : Vote catégorie (3s après le match trouvé pour laisser le temps d'afficher) ──
  setTimeout(() => {
    const room = rooms[code];
    if (!room) return;
    io.to(code).emit('category_vote_started', { categories: VOTE_CATEGORIES, duration: 10 });

    // Auto-résolution après 10s
    room.categoryVoteTimer = setTimeout(() => finalizeCategoryVote(code, io), 10000);
  }, 3000);
}

function finalizeCategoryVote(code, io) {
  const room = rooms[code];
  if (!room) return;
  clearTimeout(room.categoryVoteTimer);

  // Comptage des votes
  const counts = {};
  VOTE_CATEGORIES.forEach(c => { counts[c.id] = 0; });
  Object.values(room.categoryVotes).forEach(catId => {
    counts[catId] = (counts[catId] || 0) + 1;
  });

  // Gagnant = catégorie avec le plus de votes (égalité → random entre ex-aequo)
  const maxVotes = Math.max(...Object.values(counts));
  const winners = Object.keys(counts).filter(id => counts[id] === maxVotes);
  const chosenId = winners[Math.floor(Math.random() * winners.length)];
  const chosenLabel = VOTE_CATEGORIES.find(c => c.id === chosenId)?.label || '🌍 Toutes catégories';

  room.category = chosenId;
  room.status = 'waiting';
  io.to(code).emit('category_chosen', { categoryId: chosenId, categoryLabel: chosenLabel, votes: counts });
  console.log(`🗳️ Vote [${code}]: ${chosenLabel} (${JSON.stringify(counts)})`);

  // ── Phase 2 : Démarrage du jeu ──
  setTimeout(async () => {
    const r = rooms[code];
    if (!r) return;
    try {
      r.questions = await fetchQuestions(10, r.category, '');
      r.status = 'playing';
      io.to(code).emit('game_started', { room: sanitizeRoom(r) });
      if (r.mode === 'tactical') {
        initTacticalRoom(code, r.players, r.questions);
        setTimeout(() => startTacticalRound(code, io), 1500);
      } else {
        setTimeout(() => sendQuestion(code), 1000);
      }
    } catch(e) { console.error('MM start:', e); }
  }, 3000);
}

// Handler vote catégorie (dans io.on('connection', ...) via late registration)
// Appelé depuis le bloc io.on('connection')
function registerVoteCategoryHandler(socket, io) {
  socket.on('vote_category', ({ code, categoryId }) => {
    const room = rooms[code];
    if (!room || room.status !== 'voting') return;
    if (!VOTE_CATEGORIES.find(c => c.id === categoryId)) return;
    // Un vote par joueur
    room.categoryVotes[socket.id] = categoryId;
    // Broadcast état des votes
    const counts = {};
    VOTE_CATEGORIES.forEach(c => { counts[c.id] = 0; });
    Object.values(room.categoryVotes).forEach(id => { counts[id] = (counts[id] || 0) + 1; });
    io.to(code).emit('category_votes_update', { votes: counts, total: Object.keys(room.players).length, voted: Object.keys(room.categoryVotes).length });
    // Si tout le monde a voté → finaliser immédiatement
    if (Object.keys(room.categoryVotes).length >= Object.keys(room.players).length) {
      finalizeCategoryVote(code, io);
    }
  });
}

// ══════════════════════════════════════════
//  PARRAINAGE — referral system
//  Zéro modification de schéma :
//  • Code = 8 premiers chars de l'UUID (sans tirets, uppercase)
//  • Recherche referrer via LIKE sur id
//  • Statut "déjà parrainé" → user_metadata.referred_by (auth API)
// ══════════════════════════════════════════

function genReferralCode(userId) {
  return userId.replace(/-/g, '').substring(0, 8).toUpperCase();
}

// POST /api/apply-referral
app.post('/api/apply-referral', httpRateLimit(5), express.json(), async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) { return res.status(401).json({ error: 'Auth required' }); }
  const token = authHeader.replace('Bearer ', '');
  const { data: { user }, error: authErr } = await supa.auth.getUser(token);
  if (authErr || !user) { return res.status(403).json({ error: 'Unauthorized' }); }

  const { referral_code } = req.body;
  if (!referral_code || typeof referral_code !== 'string' || referral_code.length < 6) {
    return res.status(400).json({ error: 'Code invalide' });
  }

  try {
    const code = referral_code.toUpperCase().trim();

    // Vérifie que l'utilisateur n'a pas déjà été parrainé (via user_metadata)
    const { data: { user: fullUser } } = await supaAdmin.auth.admin.getUserById(user.id);
    if (fullUser?.user_metadata?.referred_by) {
      return res.status(400).json({ error: 'Parrainage déjà appliqué' });
    }

    // Trouve le referrer en cherchant par préfixe d'UUID
    // Code = 8 premiers chars sans tirets → UUID commence par "xxxx-xxxx-..."
    // ex: code ABCD1234 → id LIKE 'abcd1234-%'
    const uuidPrefix = (code.slice(0,8).toLowerCase() + '-').padEnd(9, '%');
    const { data: referrers } = await supaAdmin
      .from('profiles')
      .select('id, username, xp')
      .ilike('id', uuidPrefix + '%')
      .limit(1);

    const referrer = referrers?.[0];
    if (!referrer) { return res.status(404).json({ error: 'Code invalide ou introuvable' }); }
    if (referrer.id === user.id) { return res.status(400).json({ error: 'Tu ne peux pas te parrainer toi-même' }); }

    const XP_REWARD = 500;

    // XP du nouveau joueur
    const { data: newProfile } = await supaAdmin.from('profiles').select('xp').eq('id', user.id).single();

    // Applique en parallèle : XP aux deux + marquage user_metadata
    await Promise.all([
      supaAdmin.from('profiles').update({ xp: (newProfile?.xp || 0) + XP_REWARD }).eq('id', user.id),
      supaAdmin.from('profiles').update({ xp: (referrer.xp || 0) + XP_REWARD }).eq('id', referrer.id),
      supaAdmin.auth.admin.updateUserById(user.id, { user_metadata: { referred_by: referrer.id } })
    ]);

    console.log(`✅ Parrainage : ${user.id} parrainé par ${referrer.username} — +${XP_REWARD} XP chacun`);
    return res.json({ success: true, referrer: referrer.username, xp: XP_REWARD });
  } catch(e) {
    console.error('apply-referral error:', e.message);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/referral-code
app.get('/api/referral-code', httpRateLimit(20), async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) { return res.status(401).json({ error: 'Auth required' }); }
  const token = authHeader.replace('Bearer ', '');
  const { data: { user }, error: authErr } = await supa.auth.getUser(token);
  if (authErr || !user) { return res.status(403).json({ error: 'Unauthorized' }); }
  const code = genReferralCode(user.id);
  return res.json({ code, url: 'https://mindimpact.online?ref=' + code });
});

// ══════════════════════════════════════════
//  WEB PUSH — endpoints + cron hebdo
// ══════════════════════════════════════════

// Récupère la clé publique VAPID (pour le front)
app.get('/api/push/vapid-key', (req, res) => {
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY || null });
});

// Enregistre ou met à jour un abonnement push
app.post('/api/push/subscribe', httpRateLimit(10), express.json(), async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) { res.status(401).json({ error: 'Auth required' }); return; }
  const token = authHeader.replace('Bearer ', '');
  const { data: { user }, error: authErr } = await supa.auth.getUser(token);
  if (authErr || !user) { res.status(403).json({ error: 'Unauthorized' }); return; }

  const { subscription } = req.body;
  if (!subscription?.endpoint) { res.status(400).json({ error: 'Invalid subscription' }); return; }

  try {
    await supaAdmin.from('push_subscriptions').upsert({
      user_id: user.id,
      subscription,
      updated_at: new Date().toISOString()
    }, { onConflict: 'user_id' });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Désabonnement
app.post('/api/push/unsubscribe', httpRateLimit(10), express.json(), async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) { res.status(401).json({ error: 'Auth required' }); return; }
  const token = authHeader.replace('Bearer ', '');
  const { data: { user } } = await supa.auth.getUser(token);
  if (!user) { res.status(403).json({ error: 'Unauthorized' }); return; }
  await supaAdmin.from('push_subscriptions').delete().eq('user_id', user.id);
  res.json({ ok: true });
});

// ── Envoi du résumé hebdomadaire ──
async function sendWeeklySummaries() {
  if (!webpush) { console.log('⚠ Push désactivé — VAPID manquant'); return; }
  console.log('📬 Envoi du résumé hebdomadaire…');

  // Récupère tous les abonnés
  const { data: subs, error } = await supaAdmin
    .from('push_subscriptions')
    .select('user_id, subscription');
  if (error || !subs?.length) { console.log('Aucun abonné push.'); return; }

  // Pour chaque utilisateur, récupère ses stats de la semaine
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  let sent = 0, failed = 0;

  await Promise.all(subs.map(async ({ user_id, subscription }) => {
    // Récupère le profil
    const { data: profile } = await supaAdmin
      .from('profiles')
      .select('username, level, streak, total_games')
      .eq('id', user_id)
      .single();

    const username = profile?.username || 'Joueur';
    const streak   = profile?.streak   || 0;
    const level    = profile?.level    || 1;

    // Message personnalisé
    let body = `Tu as joué cette semaine ! Niveau ${level} · Streak actuel : ${streak}🔥`;
    if (streak >= 7) body = `🔥 Incroyable ${username} ! 7 jours de streak ! Continue comme ça !`;
    else if (streak === 0) body = `👋 ${username}, tu nous manques ! Reviens jouer, ta série t'attend.`;
    else if (streak >= 3) body = `⚡ ${streak} jours de suite ! Tu es en feu, ne lâche pas !`;

    const payload = JSON.stringify({
      title: '🧠 Mind Impact — Résumé de la semaine',
      body,
      icon: '/mindimpact_icon.png',
      badge: '/mindimpact_icon.png',
      url: 'https://mindimpact.online',
      tag: 'weekly-summary'
    });

    try {
      await webpush.sendNotification(subscription, payload);
      sent++;
    } catch(e) {
      failed++;
      // Supprime les abonnements expirés (410 = Gone)
      if (e.statusCode === 410) {
        await supaAdmin.from('push_subscriptions').delete().eq('user_id', user_id);
      }
    }
  }));

  console.log(`📬 Résumé hebdo envoyé: ${sent} OK, ${failed} échecs`);
}

// Cron : tous les dimanches à 19h00 (heure UTC, soit 21h FR été)
if (cron) {
  cron.schedule('0 19 * * 0', () => {
    sendWeeklySummaries();
  });
  console.log('⏰ Cron résumé hebdo activé (dim. 19h UTC)');
}

// ══════════════════════════════════════════
//  DÉMARRAGE
// ══════════════════════════════════════════
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`🚀 Mind Impact Server lancé sur le port ${PORT}`);
});

// Periodic matchmaking check (fixes starvation when no new player joins)
setInterval(() => {
  Object.keys(mmQueues).forEach(mode => {
    if (mmQueues[mode].length >= 2) tryMatchmaking(mode, io);
  });
}, 10000);

// ══════════════════════════════════════════
//  MATCHMAKING ÉQUIPE CLASSÉE
// ══════════════════════════════════════════
const teamQueue = []; // { socketId, teamId, teamName, teamTag, elo, userId, userName }


function tryMatchTeams(io) {
  if (teamQueue.length < 2) return;
  // Find two teams with closest ELO
  let bestPair = null, bestDiff = Infinity;
  for (let i = 0; i < teamQueue.length; i++) {
    for (let j = i+1; j < teamQueue.length; j++) {
      if (teamQueue[i].teamId === teamQueue[j].teamId) continue;
      const diff = Math.abs(teamQueue[i].elo - teamQueue[j].elo);
      if (diff < bestDiff) { bestDiff = diff; bestPair = [i, j]; }
    }
  }
  if (!bestPair) return;
  const [t1, t2] = [teamQueue[bestPair[0]], teamQueue[bestPair[1]]];
  teamQueue.splice(Math.max(...bestPair), 1);
  teamQueue.splice(Math.min(...bestPair), 1);

  const code = genCode();
  rooms[code] = {
    code, host: t1.socketId, status: 'waiting',
    mode: 'team_ranked', category: '0', difficulty: 'medium',
    maxQ: 10, players: {}, questions: [], currentQ: 0,
    timer: null, answers: {}, answerCount: 0,
    teamScores: { A:0, B:0 },
    teamInfo: { A: { id:t1.teamId, name:t1.teamName, tag:t1.teamTag }, B: { id:t2.teamId, name:t2.teamName, tag:t2.teamTag } }
  };

  // Add both players
  [t1, t2].forEach((t, i) => {
    rooms[code].players[t.socketId] = {
      name: t.userName || t.teamName, avatar: '⚔️',
      score: 0, lives: 3, alive: true, team: i===0?'A':'B',
      teamId: t.teamId
    };
    players[t.socketId] = { code, name: t.userName || t.teamName };
    const s = io.sockets.sockets.get(t.socketId);
    if (s) s.join(code);
  });

  io.to(t1.socketId).emit('team_match_found', { opponent: { name:t2.teamName, tag:t2.teamTag, elo:t2.elo }, roomCode: code });
  io.to(t2.socketId).emit('team_match_found', { opponent: { name:t1.teamName, tag:t1.teamTag, elo:t1.elo }, roomCode: code });
  console.log(`⚔️ Match trouvé: ${t1.teamName} VS ${t2.teamName} → Salon ${code}`);

  // Auto-start after 3s
  setTimeout(async () => {
    try {
      rooms[code].questions = await fetchQuestions(10, '0', 'medium');
      rooms[code].status = 'playing';
      io.to(code).emit('game_started', { room: sanitizeRoom(rooms[code]) });
      if (rooms[code]?.mode === 'tactical') {
        initTacticalRoom(code, rooms[code].players, rooms[code].questions);
        setTimeout(() => startTacticalRound(code, io), 1500);
      } else {
        setTimeout(() => sendQuestion(code), 1000);
      }
    } catch(e) { console.error('Erreur questions:', e); }
  }, 3000);
}

// ══════════════════════════════════════════
//  ELO SYSTEM
// ══════════════════════════════════════════

// ELO delta per rank
const ELO_TABLE = {
  Bronze:   { win:+30, loss:-10 },
  Argent:   { win:+27, loss:-13 },
  Or:       { win:+25, loss:-18 },
  Platine:  { win:+22, loss:-22 },
  Diamant:  { win:+18, loss:-25 },
  Champion: { win:+15, loss:-28 },
};

function getRankName(elo) {
  if (elo < 1200) return 'Bronze';
  if (elo < 1500) return 'Argent';
  if (elo < 1900) return 'Or';
  if (elo < 2400) return 'Platine';
  if (elo < 3000) return 'Diamant';
  return 'Champion';
}

// Called from client via socket event after team ranked game
// The client already handles solo ranked ELO
// For team ranked, we update each player's individual ELO

// ══════════════════════════════════════════
//  MODE TACTIQUE — SERVEUR
// ══════════════════════════════════════════

const TACTICAL_CONFIG = {
  TARGET_SCORE:          1000,
  BONUS_ROUND_INTERVAL:  5,
  QUESTION_POINTS: { easy:25, medium:50, hard:75 },
  INITIAL_BONUSES: ['shield', 'double', 'bomb'],
};

function getTactDifficulty() {
  const r = Math.random();
  if (r < 0.05) return 'hard';   // ~5% very hard (counts as hardcore)
  if (r < 0.25) return 'hard';   // 20% hard
  if (r < 0.60) return 'medium'; // 35% medium
  return 'easy';                 // 40% easy
}

function initTacticalRoom(code, playersObj, questions) {
  const room = rooms[code];
  if (!room) return;

  const pids = Object.keys(playersObj);
  const teamA = pids.filter((_, i) => i % 2 === 0);
  const teamB = pids.filter((_, i) => i % 2 !== 0);

  pids.forEach((pid, i) => {
    room.players[pid].team  = i % 2 === 0 ? 'A' : 'B';
    room.players[pid].alive = true;
  });

  room.tactTeamA      = teamA;
  room.tactTeamB      = teamB;
  room.tactTeamScores = { A: 0, B: 0 };
  room.tactRoundNum   = 0;
  room.tactDuelIdx    = { A: 0, B: 0 };
  room.tactAnswers    = {};
  room.tactAnswerCount = 0;

  // Give each TEAM a shared bonus pool
  room.tactBonuses    = {
    A: [...TACTICAL_CONFIG.INITIAL_BONUSES],
    B: [...TACTICAL_CONFIG.INITIAL_BONUSES],
  };

  console.log(`🎯 Tactical room init: ${code} — Éq.A: ${teamA.length} vs Éq.B: ${teamB.length}`);
}

async function startTacticalRound(code, io) {
  const room = rooms[code];
  if (!room || room.status !== 'playing') return;

  room.tactRoundNum++;
  room.tactAnswers     = {};
  room.tactAnswerCount = 0;

  const isBonus = room.tactRoundNum % TACTICAL_CONFIG.BONUS_ROUND_INTERVAL === 0;
  const diff    = getTactDifficulty();

  // Pick duellists — rotate through team members
  const teamA   = room.tactTeamA;
  const teamB   = room.tactTeamB;
  const idxA    = (room.tactDuelIdx.A++) % teamA.length;
  const idxB    = (room.tactDuelIdx.B++) % teamB.length;
  const duelAid = teamA[idxA];
  const duelBid = teamB[idxB];
  const duelA   = { id: duelAid, name: room.players[duelAid]?.name, avatar: room.players[duelAid]?.avatar };
  const duelB   = { id: duelBid, name: room.players[duelBid]?.name, avatar: room.players[duelBid]?.avatar };

  room.tactCurrentDuel = { duelAid, duelBid, isBonus, diff };

  // Fetch question
  let question;
  try {
    const qs = await fetchQuestions(1, '0', diff === 'easy' ? 'easy' : diff === 'medium' ? 'medium' : 'hard');
    question = qs[0] ? {
      q:       qs[0].q,
      answers: qs[0].answers,
      correct: qs[0].correct,
      cat:     qs[0].cat || 'Culture générale',
      diff,
    } : null;
  } catch(e) { question = null; }

  if (!question) {
    // Fallback question
    question = { q:'Combien font 2+2 ?', answers:['3','4','5','6'], correct:1, cat:'Général', diff:'easy' };
  }

  room.tactCurrentQuestion = question;

  // Emit to all
  io.to(code).emit('tactical_round_start', {
    round:      room.tactRoundNum,
    duelA,
    duelB,
    teamScores: room.tactTeamScores,
    teamWins:   room.tactTeamScores, // backward compat
    isBonus,
    question,
    bonuses:    room.tactBonuses,
    teamA:      room.tactTeamA,
    teamB:      room.tactTeamB,
  });

  // Auto timeout after 25s
  room.tactTimer = setTimeout(() => {
    resolveTacticalRound(code, io, null);
  }, 25000);
}

function resolveTacticalRound(code, io, winnerId) {
  const room = rooms[code];
  if (!room) return;
  clearTimeout(room.tactTimer);

  const { duelAid, duelBid, isBonus, diff } = room.tactCurrentDuel || {};
  const basePoints = TACTICAL_CONFIG.QUESTION_POINTS[diff] || 50;
  const points     = isBonus ? basePoints * 2 : basePoints;

  let winnerTeam = null;
  let ansA = room.tactAnswers[duelAid];
  let ansB = room.tactAnswers[duelBid];

  // Determine winner
  const correct = room.tactCurrentQuestion?.correct ?? 0;
  const aCorrect = ansA?.answerIndex === correct;
  const bCorrect = ansB?.answerIndex === correct;

  if (aCorrect && !bCorrect) winnerTeam = 'A';
  else if (bCorrect && !aCorrect) winnerTeam = 'B';
  else if (aCorrect && bCorrect) {
    // Both correct — fastest wins
    winnerTeam = (ansA?.timeLeft || 0) >= (ansB?.timeLeft || 0) ? 'A' : 'B';
  }
  // else no one correct — no points

  if (winnerTeam) {
    room.tactTeamScores[winnerTeam] = (room.tactTeamScores[winnerTeam] || 0) + points;
  }

  // Give bonus point for bonus round winner
  if (isBonus && winnerTeam) {
    const bonusTypes = ['shield', 'double', 'bomb', 'time', 'freeze'];
    const randomBonus = bonusTypes[Math.floor(Math.random() * bonusTypes.length)];
    room.tactBonuses[winnerTeam].push(randomBonus);
  }

  io.to(code).emit('tactical_round_result', {
    winner:     winnerTeam === 'A' ? duelAid : winnerTeam === 'B' ? duelBid : null,
    winnerTeam,
    teamScores: room.tactTeamScores,
    teamWins:   room.tactTeamScores,
    correct,
    ansA:       ansA?.answerIndex ?? -1,
    ansB:       ansB?.answerIndex ?? -1,
    bonusWon:   isBonus && winnerTeam ? true : false,
    bonuses:    room.tactBonuses,
    points,
  });

  // Check if match over
  const scoreA = room.tactTeamScores.A;
  const scoreB = room.tactTeamScores.B;

  if (scoreA >= TACTICAL_CONFIG.TARGET_SCORE || scoreB >= TACTICAL_CONFIG.TARGET_SCORE) {
    const matchWinner = scoreA >= TACTICAL_CONFIG.TARGET_SCORE ? 'A' : 'B';
    setTimeout(() => {
      io.to(code).emit('tactical_match_over', {
        winner:     matchWinner,
        teamScores: room.tactTeamScores,
        teamWins:   room.tactTeamScores,
        teamA:      room.tactTeamA,
        teamB:      room.tactTeamB,
      });
      room.status = 'results';
    }, 2000);
  } else {
    // Next round after 3s
    setTimeout(() => startTacticalRound(code, io), 3000);
  }
}

// ── SOCKET EVENTS TACTIQUE ──
// These are registered inside the main io.on('connection') block
// They need to be added to the existing connection handler

// ── CHRONO MODE FUNCTIONS ──
async function startChronoMode(code, io) {
  const room = rooms[code];
  if (!room) return;

  // Send first question to each player
  for (const pid of Object.keys(room.players)) {
    const s = io.sockets.sockets.get(pid);
    if (s) await sendChronoQuestion(code, pid, io);
  }

  // End game after 2 minutes
  room.chronoTimer = setTimeout(() => {
    endChronoMode(code, io);
  }, room.chronoDuration || 120000);

  // Send countdown updates every second
  let remaining = Math.ceil((room.chronoDuration || 120000) / 1000);
  room.chronoCountdown = setInterval(() => {
    remaining--;
    io.to(code).emit('chrono_countdown', { remaining });
    if (remaining <= 0) clearInterval(room.chronoCountdown);
  }, 1000);
}

async function sendChronoQuestion(code, playerId, io) {
  const room = rooms[code];
  if (!room || room.status !== 'playing') return;

  // Check time
  const elapsed = Date.now() - (room.chronoStartTime || Date.now());
  if (elapsed >= (room.chronoDuration || 120000)) return;

  try {
    const qs = await fetchQuestions(1, room.category || '0', room.difficulty || '');
    if (!qs?.[0]) return;
    const q = qs[0];
    const s = io.sockets.sockets.get(playerId);
    if (s) {
      // Store correct answer server-side (don't send to client to prevent cheating)
      if (!room.chronoCurrentAnswers) room.chronoCurrentAnswers = {};
      if (!room.chronoCurrentExpected) room.chronoCurrentExpected = {};
      room.chronoCurrentAnswers[playerId] = q.correct;
      room.chronoCurrentExpected[playerId] = q.answers ? q.answers[q.correct] : null;
      s.emit('chrono_question', {
        q:       q.q || q.question,
        qid:     q.id || null,
        answers: q.answers,
        cat:     q.cat || q.category,
        timeLeft: Math.max(0, Math.ceil(((room.chronoDuration||120000) - elapsed) / 1000)),
      });
    }
  } catch(e) { console.error('Chrono question error:', e); }
}

function endChronoMode(code, io) {
  const room = rooms[code];
  if (!room) return;
  clearInterval(room.chronoCountdown);
  clearTimeout(room.chronoTimer);
  room.status = 'results';

  const ranking = Object.entries(room.players)
    .map(([id, p]) => ({ id, name: p.name, avatar: p.avatar, score: p.chronoScore || 0, correct: p.correct || 0, combo: p.combo || 0 }))
    .sort((a, b) => b.score - a.score);

  io.to(code).emit('game_over', { ranking, mode: 'chrono' });
  console.log(`⚡ Chrono terminé: ${code}`);
  setTimeout(() => { delete rooms[code]; }, 300000);
}

function registerTacticalEvents(socket, io) {
  // Player answers during tactical round
  socket.on('tactical_answer', ({ code, answerIndex, timeLeft }) => {
    const room = rooms[code];
    if (!room || room.status !== 'playing') return;
    const { duelAid, duelBid } = room.tactCurrentDuel || {};
    if (socket.id !== duelAid && socket.id !== duelBid) return;
    if (room.tactAnswers[socket.id]) return; // already answered

    room.tactAnswers[socket.id] = { answerIndex, timeLeft };
    room.tactAnswerCount++;

    // If both duellists answered — resolve immediately
    if (room.tactAnswers[duelAid] && room.tactAnswers[duelBid]) {
      clearTimeout(room.tactTimer);
      resolveTacticalRound(code, io, null);
    }
  });

  // Use a bonus
  socket.on('tactical_use_bonus', ({ code, bonusId, targetId }) => {
    const room = rooms[code];
    if (!room) return;

    const myTeam = room.players[socket.id]?.team;
    if (!myTeam) return;

    // Check if team has this bonus
    const bonusIdx = room.tactBonuses[myTeam]?.indexOf(bonusId);
    if (bonusIdx === -1 || bonusIdx === undefined) return;

    // Remove bonus from team pool
    room.tactBonuses[myTeam].splice(bonusIdx, 1);

    const oppositeTeam = myTeam === 'A' ? 'B' : 'A';

    switch (bonusId) {
      case 'shield':
        room.tactShieldActive = room.tactShieldActive || {};
        room.tactShieldActive[myTeam] = true;
        io.to(code).emit('tactical_bonus_used', { byName: room.players[socket.id]?.name, bonus: { id:'shield', icon:'🛡️' } });
        break;

      case 'double':
        room.tactDoubleActive = myTeam;
        io.to(code).emit('tactical_bonus_used', { byName: room.players[socket.id]?.name, bonus: { id:'double', icon:'⚡' } });
        break;

      case 'bomb':
        // Check shield
        if (room.tactShieldActive?.[oppositeTeam]) {
          room.tactShieldActive[oppositeTeam] = false;
          io.to(code).emit('tactical_bonus_used', { byName: room.players[socket.id]?.name, bonus: { id:'bomb', icon:'💣' }, blocked: true });
        } else {
          room.tactTeamScores[oppositeTeam] = Math.max(0, (room.tactTeamScores[oppositeTeam] || 0) - 100);
          io.to(code).emit('tactical_bonus_used', { byName: room.players[socket.id]?.name, bonus: { id:'bomb', icon:'💣' } });
          io.to(targetId || code).emit('tactical_bomb', { points: 100 });
          io.to(code).emit('tactical_score_update', { teamScores: room.tactTeamScores });
        }
        break;

      case 'time':
        io.to(code).emit('tactical_bonus_used', { byName: room.players[socket.id]?.name, bonus: { id:'time', icon:'⏰' } });
        // Give extra time to the current duelist on myTeam
        const myDuelist = myTeam === 'A' ? room.tactCurrentDuel?.duelAid : room.tactCurrentDuel?.duelBid;
        if (myDuelist) io.to(myDuelist).emit('tactical_time_bonus', { extra: 10 });
        break;

      case 'freeze':
        if (room.tactShieldActive?.[oppositeTeam]) {
          room.tactShieldActive[oppositeTeam] = false;
          io.to(code).emit('tactical_bonus_used', { byName: room.players[socket.id]?.name, bonus: { id:'freeze', icon:'🧊' }, blocked: true });
        } else {
          io.to(code).emit('tactical_bonus_used', { byName: room.players[socket.id]?.name, bonus: { id:'freeze', icon:'🧊' } });
          const oppDuelist = oppositeTeam === 'A' ? room.tactCurrentDuel?.duelAid : room.tactCurrentDuel?.duelBid;
          if (oppDuelist) io.to(oppDuelist).emit('tactical_freeze', { duration: 10000 });
        }
        break;

      case 'target':
        // Signal to clients that team can choose next opponent
        io.to(code).emit('tactical_bonus_used', { byName: room.players[socket.id]?.name, bonus: { id:'target', icon:'🎯' } });
        room.tactNextOpponent = targetId;
        break;
    }

    // Broadcast updated bonuses
    io.to(code).emit('tactical_bonuses_update', { bonuses: room.tactBonuses });
  });
}
