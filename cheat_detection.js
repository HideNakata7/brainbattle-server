// Détection de triche pour Mind Impact.
// Approche : analyse statistique (gratuite) + flag pour review admin.
// Pas d'auto-ban — uniquement signal pour modération humaine (faux positifs possibles).
//
// Hooks à appeler depuis server.js :
//   recordAnswer(userId, isCorrect, responseTimeMs, difficulty)
//   recordGameResult(userId, mode, score, eloChange, durationSec)
//   getSuspicionReport(userId) → { score, reasons }
//   getFlaggedUsers()         → liste des comptes à examiner

// Configuration des seuils
const CONFIG = {
  // Temps de réponse — humain rapide = ~1500ms, expert = ~800ms, bot = <500ms
  MIN_HUMAN_RESPONSE_MS: 600,
  SUSPICIOUS_AVG_RESPONSE_MS: 900,

  // Accuracy par difficulté
  MAX_NORMAL_ACCURACY_HARD: 0.92,    // >92% sur hard = louche (sauf expert)
  MAX_NORMAL_ACCURACY_HARDCORE: 0.85,

  // Variance temporelle — un humain a une variance, un bot non
  MIN_HUMAN_VARIANCE_MS: 300,

  // Streak anormal
  MAX_NORMAL_WIN_STREAK: 25,         // 25 victoires d'affilée = suspect

  // ELO progression
  MAX_NORMAL_ELO_PER_DAY: 500,

  // Volume minimum pour considérer les stats
  MIN_ANSWERS_FOR_FLAG: 30,
  MIN_GAMES_FOR_FLAG: 5,
};

// Stockage en mémoire (peut être persisté en BDD plus tard)
const playerStats = new Map();

function getStats(userId){
  if (!playerStats.has(userId)){
    playerStats.set(userId, {
      userId,
      answers: [],          // {correct, timeMs, difficulty, ts}
      games: [],            // {mode, score, eloChange, durationSec, ts}
      flags: [],            // raisons des suspicions
      createdAt: Date.now()
    });
  }
  return playerStats.get(userId);
}

function recordAnswer(userId, isCorrect, responseTimeMs, difficulty = 'medium'){
  if (!userId || typeof responseTimeMs !== 'number') return;
  const s = getStats(userId);
  s.answers.push({ correct: !!isCorrect, timeMs: responseTimeMs, difficulty, ts: Date.now() });
  // Garde max 500 dernières réponses
  if (s.answers.length > 500) s.answers.shift();
}

function recordGameResult(userId, mode, score, eloChange = 0, durationSec = 0){
  if (!userId || !mode) return;
  const s = getStats(userId);
  s.games.push({ mode, score: score|0, eloChange: eloChange|0, durationSec: durationSec|0, ts: Date.now() });
  if (s.games.length > 200) s.games.shift();
}

// Calcule statistiques d'un joueur
function computeMetrics(s){
  const m = {
    totalAnswers: s.answers.length,
    totalGames: s.games.length,
    avgResponseMs: 0,
    medianResponseMs: 0,
    minResponseMs: Infinity,
    accuracyHard: 0,
    accuracyHardcore: 0,
    varianceMs: 0,
    winStreak: 0,
    eloLast24h: 0,
    fastResponseRate: 0,    // % de réponses < 600ms
    suspiciousPatternScore: 0,
  };

  if (s.answers.length === 0) return m;

  const times = s.answers.map(a => a.timeMs).sort((a,b)=>a-b);
  m.avgResponseMs = Math.round(times.reduce((a,b)=>a+b,0) / times.length);
  m.medianResponseMs = times[Math.floor(times.length/2)];
  m.minResponseMs = times[0];
  m.fastResponseRate = s.answers.filter(a => a.timeMs < CONFIG.MIN_HUMAN_RESPONSE_MS).length / s.answers.length;

  // Variance (écart-type) des temps de réponse
  const mean = m.avgResponseMs;
  const variance = times.reduce((sum, t) => sum + (t - mean)**2, 0) / times.length;
  m.varianceMs = Math.round(Math.sqrt(variance));

  // Accuracy par difficulté
  const hardAnswers = s.answers.filter(a => a.difficulty === 'hard');
  const hardcoreAnswers = s.answers.filter(a => a.difficulty === 'hardcore');
  m.accuracyHard = hardAnswers.length ? hardAnswers.filter(a=>a.correct).length / hardAnswers.length : 0;
  m.accuracyHardcore = hardcoreAnswers.length ? hardcoreAnswers.filter(a=>a.correct).length / hardcoreAnswers.length : 0;

  // Streak (sur les jeux compétitifs)
  let streak = 0;
  for (let i = s.games.length - 1; i >= 0; i--){
    if (s.games[i].eloChange > 0) streak++;
    else break;
  }
  m.winStreak = streak;

  // ELO sur 24h
  const cutoff = Date.now() - 24 * 3600 * 1000;
  m.eloLast24h = s.games.filter(g => g.ts > cutoff).reduce((sum, g) => sum + g.eloChange, 0);

  return m;
}

// Calcule score de suspicion 0-100
function getSuspicionReport(userId){
  const s = playerStats.get(userId);
  if (!s) return { score: 0, reasons: [], metrics: null };

  const m = computeMetrics(s);
  let score = 0;
  const reasons = [];

  if (m.totalAnswers < CONFIG.MIN_ANSWERS_FOR_FLAG){
    return { score: 0, reasons: ['volume_insuffisant'], metrics: m };
  }

  // 1. Réponses trop rapides
  if (m.minResponseMs < 200){
    score += 30; reasons.push('reponse_minimum_<200ms');
  } else if (m.minResponseMs < 400){
    score += 15; reasons.push('reponse_minimum_<400ms');
  }
  if (m.avgResponseMs < CONFIG.SUSPICIOUS_AVG_RESPONSE_MS && m.totalAnswers > 50){
    score += 25; reasons.push('moyenne_<' + CONFIG.SUSPICIOUS_AVG_RESPONSE_MS + 'ms');
  }
  if (m.fastResponseRate > 0.5){
    score += 20; reasons.push('plus_de_50%_reponses_<600ms');
  }

  // 2. Variance trop faible (timing de bot)
  if (m.varianceMs < CONFIG.MIN_HUMAN_VARIANCE_MS && m.totalAnswers > 50){
    score += 25; reasons.push('variance_temporelle_anormale');
  }

  // 3. Accuracy trop haute
  if (m.accuracyHardcore > CONFIG.MAX_NORMAL_ACCURACY_HARDCORE && m.totalAnswers > 30){
    score += 20; reasons.push('accuracy_hardcore_>85%');
  }
  if (m.accuracyHard > CONFIG.MAX_NORMAL_ACCURACY_HARD && m.totalAnswers > 50){
    score += 15; reasons.push('accuracy_hard_>92%');
  }

  // 4. Win streak
  if (m.winStreak > CONFIG.MAX_NORMAL_WIN_STREAK){
    score += 20; reasons.push('streak_>' + CONFIG.MAX_NORMAL_WIN_STREAK);
  }

  // 5. ELO climb
  if (m.eloLast24h > CONFIG.MAX_NORMAL_ELO_PER_DAY){
    score += 15; reasons.push('elo_24h_>' + CONFIG.MAX_NORMAL_ELO_PER_DAY);
  }

  return { score: Math.min(100, score), reasons, metrics: m };
}

// Liste des joueurs flaggués (score >= seuil)
function getFlaggedUsers(threshold = 50){
  const flagged = [];
  for (const userId of playerStats.keys()){
    const r = getSuspicionReport(userId);
    if (r.score >= threshold){
      flagged.push({ userId, score: r.score, reasons: r.reasons });
    }
  }
  return flagged.sort((a,b) => b.score - a.score);
}

// Expose les compteurs pour debug
function getStatsSummary(){
  return {
    totalPlayers: playerStats.size,
    totalAnswers: Array.from(playerStats.values()).reduce((s, p) => s + p.answers.length, 0),
    flaggedCount: getFlaggedUsers().length
  };
}

module.exports = {
  recordAnswer,
  recordGameResult,
  getSuspicionReport,
  getFlaggedUsers,
  getStatsSummary,
};
