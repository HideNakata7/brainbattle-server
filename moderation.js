// Modération chat + pseudo via Claude Haiku 4.5 (rapide & peu cher)
// Stratégie : pre-filter local → API call seulement si nécessaire → cache LRU pour les répétitions.

const Anthropic = require('@anthropic-ai/sdk');

const client = process.env.ANTHROPIC_API_KEY ? new Anthropic() : null;
const MOD_MODEL = 'claude-haiku-4-5-20251001';

// Cache LRU simple (clé = texte normalisé, valeur = verdict)
const CACHE_MAX = 5000;
const cache = new Map();
function cacheGet(k){ if (cache.has(k)){ const v = cache.get(k); cache.delete(k); cache.set(k, v); return v; } return null; }
function cacheSet(k, v){ if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value); cache.set(k, v); }

// ═══════════════════════════════════════════
//  PRE-FILTERS (sans LLM, instant + gratuit)
// ═══════════════════════════════════════════

const HARD_BLOCKLIST = [
  // Slurs racistes/homophobes/etc — match strict
  /\b(?:n[i1l]gg[ae3]r|fagg?[oe]t|tr[a4]nn[i1y]|kik[e3]|chink|sp[i1]c|w[e3]tback)\b/i,
  // Termes pédophiles
  /\b(?:pedo|p[e3]d[o0]phil[ea])\b/i,
  // Mots français très lourds (insultes ciblées)
  /\b(?:n[e3]gr[oe](?:s|sse)?|p[e3]d[e3](?:s)?|pute|salope|enc[uû]l[eé]?)\b/i,
];

const CONTACT_PATTERNS = [
  /\b\d{2}[\s.-]?\d{2}[\s.-]?\d{2}[\s.-]?\d{2}[\s.-]?\d{2}\b/,                // tel FR
  /\b\d{3}[\s.-]?\d{3}[\s.-]?\d{4}\b/,                                         // tel autre
  /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/,                                              // email
  /\b(?:discord|tiktok|insta(?:gram)?|snap|whatsapp|telegram|wechat)[\s:.]+[\w._-]{3,}/i,
  /\bdm\s+me\b/i,
];

const SPAM_PATTERNS = [
  /(.)\1{6,}/,              // aaaaaaa
  /^(\w+\s*)\1{4,}$/,       // mot répété
  /https?:\/\/(?!mindimpact\.online|brainbattle\.fr)/i, // URL externe
  /\b(?:bit\.ly|tinyurl|t\.me|wa\.me)\b/i,             // raccourcisseurs
];

function normalize(s){ return (s||'').toLowerCase().trim(); }

function preFilter(msg){
  const m = msg || '';
  if (m.length === 0) return { ok:false, reason:'empty', source:'pre' };
  if (m.length > 500)  return { ok:false, reason:'too_long', source:'pre' };
  if (HARD_BLOCKLIST.some(r => r.test(m))) return { ok:false, reason:'slur', source:'pre' };
  if (CONTACT_PATTERNS.some(r => r.test(m))) return { ok:false, reason:'contact_share', source:'pre' };
  if (SPAM_PATTERNS.some(r => r.test(m))) return { ok:false, reason:'spam', source:'pre' };
  return null; // pas de verdict encore, laisser passer au LLM si dispo
}

// ═══════════════════════════════════════════
//  CHAT MESSAGE MODERATION
// ═══════════════════════════════════════════

const CHAT_SYSTEM = `Tu modères le chat d'un jeu de quiz compétitif (Mind Impact, ado/adultes 13+).

Pour chaque message, décide :
- "OK" si le message est acceptable
- "BLOCK" si le message contient :
  • insulte ciblée vers un autre joueur
  • harcèlement, menace, discrimination
  • contenu sexuel/explicit
  • partage de contact (tel, email, réseaux sociaux)
  • spam, lien externe, arnaque
  • incitation à la haine

ATTENTION — NE BLOQUE PAS :
- Frustration personnelle non-ciblée ("putain j'ai perdu", "mince mauvaise réponse")
- Compétition saine ("ggwp", "trop fort", "je vais te battre")
- Sujets de quiz (mentions de personnages historiques, films, animaux, etc.)

RÉPONDS UNIQUEMENT par : "OK" ou "BLOCK:<motif court>"
Ex: "OK" / "BLOCK:insulte" / "BLOCK:contact" / "BLOCK:menace"`;

async function moderateChatMessage(msg){
  const norm = normalize(msg);
  if (!norm) return { ok:false, reason:'empty', source:'pre' };

  const cached = cacheGet('chat:' + norm);
  if (cached) return { ...cached, source:'cache' };

  const pre = preFilter(msg);
  if (pre){
    cacheSet('chat:' + norm, pre);
    return pre;
  }

  // Si LLM indispo, fallback en passe-tout après pre-filter (déjà filtré le pire)
  if (!client) return { ok:true, source:'no_llm' };

  try {
    const resp = await client.messages.create({
      model: MOD_MODEL,
      max_tokens: 30,
      system: [{ type:'text', text: CHAT_SYSTEM, cache_control:{type:'ephemeral'} }],
      messages: [{ role:'user', content: msg }]
    });
    const text = (resp.content[0]?.text || '').trim();
    let result;
    if (/^OK\b/i.test(text)) result = { ok:true, source:'llm' };
    else if (/^BLOCK/i.test(text)){
      const reason = (text.match(/BLOCK[:\s]+(.+)/i)?.[1] || 'inapproprie').trim().slice(0, 30);
      result = { ok:false, reason, source:'llm' };
    } else {
      // réponse inattendue → laisser passer (fail-open pour éviter de censurer à tort)
      result = { ok:true, source:'llm_unclear' };
    }
    cacheSet('chat:' + norm, result);
    return result;
  } catch(e){
    console.warn('[moderation] chat LLM error:', e.message);
    return { ok:true, source:'llm_error' }; // fail-open
  }
}

// ═══════════════════════════════════════════
//  PSEUDO MODERATION
// ═══════════════════════════════════════════

const PSEUDO_SYSTEM = `Tu modères les pseudos d'un jeu accessible aux 13 ans et plus (Mind Impact).

REJETTE si le pseudo :
- Contient une insulte, slur, terme raciste/homophobe/discriminatoire
- Évoque sexe, drogue, violence, suicide
- Imite un membre du staff ("admin", "moderator", "support", "MindImpact")
- Imite une marque protégée
- Est une combinaison de chiffres seuls
- Contient un domaine, email, contact

ACCEPTE :
- Pseudos normaux (ProDuQuiz, FluffyCat, Bastien98, etc.)
- Personnages fictifs neutres (Naruto, Goku, Kratos)
- Combinaisons fantaisistes propres

RÉPONDS UNIQUEMENT par : "OK" ou "BLOCK:<motif court>"`;

async function moderatePseudo(pseudo){
  const norm = normalize(pseudo);
  if (!norm) return { ok:false, reason:'empty' };
  if (norm.length < 2)  return { ok:false, reason:'too_short' };
  if (norm.length > 24) return { ok:false, reason:'too_long' };
  if (!/^[a-z0-9_.\-àâäéèêëïîôöùûüÿñç]+$/i.test(pseudo)) return { ok:false, reason:'invalid_chars' };

  const cached = cacheGet('pseudo:' + norm);
  if (cached) return { ...cached, source:'cache' };

  if (HARD_BLOCKLIST.some(r => r.test(pseudo))){
    const r = { ok:false, reason:'slur', source:'pre' };
    cacheSet('pseudo:' + norm, r);
    return r;
  }
  if (/^(?:admin|administrateur|moderator|moderateur|support|staff|mindimpact|mind_impact|brainbattle)$/i.test(pseudo)){
    const r = { ok:false, reason:'staff_impersonation', source:'pre' };
    cacheSet('pseudo:' + norm, r);
    return r;
  }

  if (!client) return { ok:true, source:'no_llm' };

  try {
    const resp = await client.messages.create({
      model: MOD_MODEL,
      max_tokens: 30,
      system: [{ type:'text', text: PSEUDO_SYSTEM, cache_control:{type:'ephemeral'} }],
      messages: [{ role:'user', content: 'Pseudo : ' + pseudo }]
    });
    const text = (resp.content[0]?.text || '').trim();
    let result;
    if (/^OK\b/i.test(text)) result = { ok:true, source:'llm' };
    else if (/^BLOCK/i.test(text)){
      const reason = (text.match(/BLOCK[:\s]+(.+)/i)?.[1] || 'inapproprie').trim().slice(0, 30);
      result = { ok:false, reason, source:'llm' };
    } else {
      result = { ok:true, source:'llm_unclear' };
    }
    cacheSet('pseudo:' + norm, result);
    return result;
  } catch(e){
    console.warn('[moderation] pseudo LLM error:', e.message);
    return { ok:true, source:'llm_error' };
  }
}

module.exports = { moderateChatMessage, moderatePseudo };
