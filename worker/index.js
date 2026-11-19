// claude-prime-api : enregistre les fiches (R2) et les commentaires (D1) de outils.html.
//
// Stockage R2 (liaison DATA) :
//   outils/<outilId>.json               une fiche par outil (avec "version"), ex. outils/outil-001.json
//   commentaires/<outilId>/<uuid>.json  ANCIENS commentaires : plus aucune écriture ici, seulement
//                                       relus (et repris dans D1 sur demande). Jamais supprimés.
//
// Stockage D1 (liaison DB, table commentaires, voir migrations/0001_commentaires.sql) :
//   tous les nouveaux commentaires. Toutes les requêtes passent par prepare().bind() :
//   aucune valeur n'est jamais collée dans le texte SQL.
//
// Routes (la page les appelle sur son propre domaine, via functions/api/[[path]].js) :
//   GET  /api/outils                          lecture publique des fiches et commentaires
//   GET  /api/outils/:id/commentaires         les 20 derniers commentaires d'un outil (public),
//                                             puis ?avant=<curseur> pour les 20 précédents
//   GET  /api/edit/session                    qui est connecté (protégé)
//   GET  /api/edit/connexion?retour=/...      passe par Cloudflare Access puis revient (protégé)
//   POST /api/edit/init                       crée les fiches absentes, n'écrase jamais (protégé)
//   PUT  /api/edit/outils/:id                 modifie une fiche, contrôle de version (protégé)
//   POST /api/edit/outils/:id/commentaires    ajoute un commentaire dans D1 (protégé)
//   GET  /api/edit/reprise-commentaires       simulation de la reprise R2 -> D1, n'écrit rien (protégé)
//   POST /api/edit/reprise-commentaires       reprise R2 -> D1 : copie, sans doublon, sans rien
//                                             supprimer de R2 ; peut être relancée sans risque (protégé)
//
// Tâche planifiée (wrangler.jsonc > triggers.crons) : supprime de D1 les commentaires plus vieux
// que DUREE_CONSERVATION_MOIS mois (12 par défaut).
//
// Protection : tout ce qui écrit exige un jeton Cloudflare Access valide, vérifié ICI
// (signature RS256, audience, émetteur, expiration). Si ACCESS_TEAM_DOMAIN ou ACCESS_AUD
// ne sont pas réglés, toute écriture est refusée (édition désactivée).
// En plus (pas à la place) : l'origine doit être ALLOWED_ORIGIN, et si Turnstile est réglé
// (TURNSTILE_SITE_KEY + secret TURNSTILE_SECRET_KEY), chaque soumission doit porter un jeton
// Turnstile valide pour TURNSTILE_ACTION et TURNSTILE_HOSTNAME.

export const SECTIONS = ['code', 'app', 'contexte', 'tests', 'deploiement', 'espaces', 'inspiration'];
export const TYPES_PERSO = ['texte', 'booleen', 'date', 'liste', 'url'];

export const LIMITES = {
  corps: 64 * 1024,      // taille max d'une requête, en octets
  nom: 120,
  mention: 120,
  url: 2048,
  format: 40,
  usage: 1000,
  acces: 1000,
  lienInteret: 500,
  persoNombre: 20,
  persoCle: 60,
  persoTexte: 1000,
  listeNombre: 50,
  listeElement: 200,
  commentaire: 2000,
  initNombre: 500,
  pageCommentaires: 20,  // commentaires par page sur /api/outils/:id/commentaires
  purgeLot: 500,         // lignes supprimées par requête lors de la purge
};

const ID_OUTIL = /^outil-\d{3,6}$/;
const DATE_ISO = /^\d{4}-\d{2}-\d{2}$/;
const CHAMPS = ['section', 'nom', 'mention', 'url', 'format', 'usage', 'acces', 'verifieLe', 'lienInteret'];

// ---------- Réponses ----------

function json(donnees, statut = 200, extra = {}) {
  return new Response(JSON.stringify(donnees), {
    status: statut,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...extra,
    },
  });
}

const erreur = (statut, message, extra = {}) => json({ erreur: message, ...extra }, statut);

// ---------- Validation ----------

class Invalide extends Error {}

function texte(valeur, nomChamp, max, { vide = true } = {}) {
  if (typeof valeur !== 'string') throw new Invalide(`${nomChamp} : texte attendu`);
  const v = valeur.trim();
  if (!vide && v === '') throw new Invalide(`${nomChamp} : obligatoire`);
  if (v.length > max) throw new Invalide(`${nomChamp} : ${max} caractères maximum`);
  return v;
}

function texteOuNull(valeur, nomChamp, max) {
  if (valeur === null) return null;
  const v = texte(valeur, nomChamp, max);
  return v === '' ? null : v;
}

export function urlValide(valeur) {
  if (typeof valeur !== 'string' || valeur.length > LIMITES.url) return false;
  try {
    const u = new URL(valeur);
    return (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname !== '';
  } catch {
    return false;
  }
}

function url(valeur, nomChamp) {
  if (!urlValide(valeur)) throw new Invalide(`${nomChamp} : adresse http ou https valide attendue`);
  return valeur;
}

function dateValide(valeur) {
  if (typeof valeur !== 'string' || !DATE_ISO.test(valeur)) return false;
  const d = new Date(valeur + 'T00:00:00Z');
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === valeur;
}

function dateOuNull(valeur, nomChamp) {
  if (valeur === null) return null;
  if (!dateValide(valeur)) throw new Invalide(`${nomChamp} : date AAAA-MM-JJ attendue`);
  return valeur;
}

function objetStrict(valeur, nomChamp, cles) {
  if (!valeur || typeof valeur !== 'object' || Array.isArray(valeur)) {
    throw new Invalide(`${nomChamp} : objet attendu`);
  }
  for (const cle of Object.keys(valeur)) {
    if (!cles.includes(cle)) throw new Invalide(`${nomChamp} : champ inconnu « ${cle} »`);
  }
}

export function validerChamps(c) {
  objetStrict(c, 'champs', CHAMPS);
  for (const cle of CHAMPS) {
    if (!(cle in c)) throw new Invalide(`champs : « ${cle} » manquant`);
  }
  if (!SECTIONS.includes(c.section)) throw new Invalide('section : valeur inconnue');
  return {
    section: c.section,
    nom: texte(c.nom, 'nom', LIMITES.nom, { vide: false }),
    mention: texte(c.mention, 'mention', LIMITES.mention),
    url: url(c.url, 'url'),
    format: texteOuNull(c.format, 'format', LIMITES.format),
    usage: texte(c.usage, 'usage', LIMITES.usage),
    acces: texteOuNull(c.acces, 'acces', LIMITES.acces),
    verifieLe: dateOuNull(c.verifieLe, 'verifieLe'),
    lienInteret: texteOuNull(c.lienInteret, 'lienInteret', LIMITES.lienInteret),
  };
}

export function validerPerso(liste) {
  if (!Array.isArray(liste)) throw new Invalide('perso : liste attendue');
  if (liste.length > LIMITES.persoNombre) throw new Invalide(`perso : ${LIMITES.persoNombre} champs maximum`);
  const vues = new Set();
  return liste.map((p, i) => {
    const nom = `perso[${i}]`;
    objetStrict(p, nom, ['cle', 'type', 'valeur']);
    const cle = texte(p.cle, `${nom}.cle`, LIMITES.persoCle, { vide: false });
    if (vues.has(cle.toLowerCase())) throw new Invalide(`${nom}.cle : « ${cle} » en double`);
    vues.add(cle.toLowerCase());
    if (!TYPES_PERSO.includes(p.type)) throw new Invalide(`${nom}.type : type inconnu`);
    let valeur;
    switch (p.type) {
      case 'texte':
        valeur = texte(p.valeur, `${nom}.valeur`, LIMITES.persoTexte);
        break;
      case 'booleen':
        if (typeof p.valeur !== 'boolean') throw new Invalide(`${nom}.valeur : vrai ou faux attendu`);
        valeur = p.valeur;
        break;
      case 'date':
        valeur = dateOuNull(p.valeur, `${nom}.valeur`);
        break;
      case 'liste':
        if (!Array.isArray(p.valeur)) throw new Invalide(`${nom}.valeur : liste attendue`);
        if (p.valeur.length > LIMITES.listeNombre) {
          throw new Invalide(`${nom}.valeur : ${LIMITES.listeNombre} éléments maximum`);
        }
        valeur = p.valeur
          .map((v, j) => texte(v, `${nom}.valeur[${j}]`, LIMITES.listeElement))
          .filter((v) => v !== '');
        break;
      case 'url':
        valeur = url(p.valeur, `${nom}.valeur`);
        break;
    }
    return { cle, type: p.type, valeur };
  });
}

async function lireCorps(request) {
  const type = request.headers.get('content-type') || '';
  if (!type.toLowerCase().startsWith('application/json')) {
    throw new Invalide('Content-Type application/json attendu');
  }
  const brut = await request.text();
  if (new TextEncoder().encode(brut).length > LIMITES.corps) throw new Invalide('requête trop grosse');
  try {
    return JSON.parse(brut);
  } catch {
    throw new Invalide('JSON illisible');
  }
}

// ---------- Authentification Cloudflare Access ----------

function accessConfigure(env) {
  return (
    typeof env.ACCESS_TEAM_DOMAIN === 'string' &&
    /^[a-z0-9-]+\.cloudflareaccess\.com$/.test(env.ACCESS_TEAM_DOMAIN) &&
    typeof env.ACCESS_AUD === 'string' &&
    /^[a-f0-9]{32,128}$/.test(env.ACCESS_AUD)
  );
}

// Turnstile : 'actif' (clé publique + secret), 'absent' (aucun des deux) ou 'incomplet'.
function etatTurnstile(env) {
  const site = !!env.TURNSTILE_SITE_KEY;
  const secret = !!env.TURNSTILE_SECRET_KEY;
  if (site && secret) return 'actif';
  return site || secret ? 'incomplet' : 'absent';
}

export function editionConfiguree(env) {
  return accessConfigure(env) && etatTurnstile(env) !== 'incomplet';
}

const actionTurnstile = (env) => env.TURNSTILE_ACTION || 'soumission';

// Vérifie le jeton Turnstile auprès de Cloudflare. Renvoie null si OK, sinon un message.
async function verifierTurnstile(request, env) {
  if (etatTurnstile(env) !== 'actif') return null;
  const jeton = request.headers.get('cf-turnstile-response');
  if (!jeton || jeton.length > 2048) return 'Vérification anti-robot manquante.';
  const form = new FormData();
  form.append('secret', env.TURNSTILE_SECRET_KEY);
  form.append('response', jeton);
  const ip = request.headers.get('cf-connecting-ip');
  if (ip) form.append('remoteip', ip);
  let resultat;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
    resultat = await r.json();
  } catch {
    return 'Vérification anti-robot indisponible pour le moment.';
  }
  if (!resultat || resultat.success !== true) return 'Vérification anti-robot refusée.';
  if (resultat.action !== actionTurnstile(env)) return 'Vérification anti-robot : action inattendue.';
  if (env.TURNSTILE_HOSTNAME && resultat.hostname !== env.TURNSTILE_HOSTNAME) {
    return 'Vérification anti-robot : site inattendu.';
  }
  return null;
}

const cacheCles = { equipe: null, cles: [], expire: 0 };

async function clesAccess(equipe, forcer = false) {
  const maintenant = Date.now();
  if (!forcer && cacheCles.equipe === equipe && cacheCles.expire > maintenant) return cacheCles.cles;
  const reponse = await fetch(`https://${equipe}/cdn-cgi/access/certs`);
  if (!reponse.ok) throw new Error('certificats Access indisponibles');
  const { keys } = await reponse.json();
  Object.assign(cacheCles, { equipe, cles: Array.isArray(keys) ? keys : [], expire: maintenant + 10 * 60 * 1000 });
  return cacheCles.cles;
}

function base64url(segment) {
  const b64 = segment.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function verifierJeton(jeton, env) {
  const morceaux = jeton.split('.');
  if (morceaux.length !== 3) return null;
  let entete, charge;
  try {
    entete = JSON.parse(new TextDecoder().decode(base64url(morceaux[0])));
    charge = JSON.parse(new TextDecoder().decode(base64url(morceaux[1])));
  } catch {
    return null;
  }
  if (entete.alg !== 'RS256' || typeof entete.kid !== 'string') return null;

  const equipe = env.ACCESS_TEAM_DOMAIN;
  let jwk = (await clesAccess(equipe)).find((k) => k.kid === entete.kid);
  if (!jwk) jwk = (await clesAccess(equipe, true)).find((k) => k.kid === entete.kid); // rotation des clés
  if (!jwk) return null;

  const cle = await crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const signe = new TextEncoder().encode(`${morceaux[0]}.${morceaux[1]}`);
  const valide = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cle, base64url(morceaux[2]), signe);
  if (!valide) return null;

  const maintenant = Math.floor(Date.now() / 1000);
  const audiences = Array.isArray(charge.aud) ? charge.aud : [charge.aud];
  if (!audiences.includes(env.ACCESS_AUD)) return null;
  if (charge.iss !== `https://${equipe}`) return null;
  if (typeof charge.exp !== 'number' || charge.exp <= maintenant) return null;
  if (typeof charge.nbf === 'number' && charge.nbf > maintenant + 60) return null;

  const email = typeof charge.email === 'string' ? charge.email : null;
  if (!email) return null; // jeton de service sans personne identifiée : refusé
  return { email };
}

function lireCookie(request, nom) {
  const cookies = request.headers.get('cookie') || '';
  for (const morceau of cookies.split(';')) {
    const [cle, ...reste] = morceau.trim().split('=');
    if (cle === nom) return reste.join('=');
  }
  return null;
}

// Renvoie { utilisateur } ou { reponse } (refus déjà construit).
async function exigerUtilisateur(request, env) {
  if (!accessConfigure(env)) {
    return { reponse: erreur(503, 'Modification désactivée : protection Cloudflare Access non configurée.') };
  }
  if (etatTurnstile(env) === 'incomplet') {
    return { reponse: erreur(503, 'Modification désactivée : Turnstile à moitié configuré (clé publique ou secret manquant).') };
  }
  const jeton = request.headers.get('cf-access-jwt-assertion') || lireCookie(request, 'CF_Authorization');
  if (!jeton) return { reponse: erreur(401, 'Connexion requise.') };
  let utilisateur = null;
  try {
    utilisateur = await verifierJeton(jeton, env);
  } catch {
    return { reponse: erreur(503, 'Vérification de la connexion impossible pour le moment.') };
  }
  if (!utilisateur) return { reponse: erreur(401, 'Connexion invalide ou expirée.') };
  return { utilisateur };
}

// Bloque les écritures venant d'un autre site (le navigateur envoie Origin).
// ALLOWED_ORIGIN = adresse réelle du site, ex. https://claude-prime-c6r.pages.dev
function origineAutorisee(request, env) {
  const origine = request.headers.get('origin');
  if (!origine) return true;
  return origine === (env.ALLOWED_ORIGIN || new URL(request.url).origin);
}

// ---------- R2 ----------

const cleFiche = (id) => `outils/${id}.json`;

async function listerCles(bucket, prefixe) {
  const cles = [];
  let curseur;
  do {
    const page = await bucket.list({ prefix: prefixe, cursor: curseur, limit: 1000 });
    for (const o of page.objects) cles.push(o.key);
    curseur = page.truncated ? page.cursor : undefined;
  } while (curseur);
  return cles;
}

async function lireJson(bucket, cle) {
  const objet = await bucket.get(cle);
  return objet ? { donnees: await objet.json(), etag: objet.etag } : null;
}

// Anciens commentaires restés dans R2 (avant le passage à D1). Lecture seule.
async function anciensCommentairesR2(env) {
  const cles = await listerCles(env.DATA, 'commentaires/');
  const objets = await Promise.all(cles.map((c) => lireJson(env.DATA, c)));
  return objets.filter(Boolean).map((o) => o.donnees);
}

// Un ancien commentaire R2 est-il bien formé ? (la reprise ignore les autres, sans rien casser)
function commentaireR2Valide(c) {
  return (
    c && typeof c === 'object' &&
    typeof c.id === 'string' && /^[0-9a-f-]{36}$/.test(c.id) &&
    typeof c.outilId === 'string' && ID_OUTIL.test(c.outilId) &&
    typeof c.texte === 'string' && c.texte.length > 0 && c.texte.length <= LIMITES.commentaire &&
    typeof c.auteur === 'string' && c.auteur.length > 0 &&
    typeof c.creeLe === 'string' && !Number.isNaN(Date.parse(c.creeLe))
  );
}

// ---------- D1 ----------

// Ligne SQL -> objet renvoyé à la page (mêmes noms qu'avant : outilId, creeLe).
const versCommentaire = (l) => ({ id: l.id, outilId: l.outil_id, texte: l.texte, auteur: l.auteur, creeLe: l.cree_le });

// Date limite de conservation : maintenant moins N mois (N = DUREE_CONSERVATION_MOIS, 12 par défaut).
export function dateLimite(env, maintenant = new Date()) {
  const n = Number.parseInt(env.DUREE_CONSERVATION_MOIS ?? '12', 10);
  const mois = Number.isInteger(n) && n > 0 ? n : 12;
  const d = new Date(maintenant.getTime());
  d.setUTCMonth(d.getUTCMonth() - mois);
  return d.toISOString();
}

// Curseur de pagination : « commentaires plus anciens que (creeLe, id) ». Opaque pour la page.
function encoderCurseur(l) {
  return btoa(JSON.stringify([l.cree_le, l.id])).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decoderCurseur(valeur) {
  try {
    const [creeLe, id] = JSON.parse(new TextDecoder().decode(base64url(valeur)));
    if (typeof creeLe === 'string' && typeof id === 'string' && creeLe.length <= 40 && id.length <= 40) {
      return { creeLe, id };
    }
  } catch { /* curseur illisible */ }
  throw new Invalide('avant : curseur invalide');
}

// GET /api/outils/:id/commentaires[?avant=<curseur>] : 20 commentaires, du plus récent au plus ancien.
async function listerCommentaires(env, id, avant) {
  const limite = LIMITES.pageCommentaires;
  const curseur = avant ? decoderCurseur(avant) : null;
  // On lit un commentaire de plus que la page pour savoir s'il en reste après.
  const requete = curseur
    ? env.DB.prepare(
      `SELECT id, outil_id, texte, auteur, cree_le FROM commentaires
       WHERE outil_id = ?1 AND (cree_le < ?2 OR (cree_le = ?2 AND id < ?3))
       ORDER BY cree_le DESC, id DESC LIMIT ?4`,
    ).bind(id, curseur.creeLe, curseur.id, limite + 1)
    : env.DB.prepare(
      `SELECT id, outil_id, texte, auteur, cree_le FROM commentaires
       WHERE outil_id = ?1
       ORDER BY cree_le DESC, id DESC LIMIT ?2`,
    ).bind(id, limite + 1);
  const { results } = await requete.all();
  const page = results.slice(0, limite);
  const suivant = results.length > limite ? encoderCurseur(page[page.length - 1]) : null;
  return json({ outilId: id, commentaires: page.map(versCommentaire), suivant });
}

// Tâche planifiée : supprime par lots les commentaires D1 plus vieux que la date limite.
export async function purgerCommentaires(env, maintenant = new Date()) {
  const limite = dateLimite(env, maintenant);
  const suppression = env.DB.prepare(
    `DELETE FROM commentaires WHERE id IN (
       SELECT id FROM commentaires WHERE cree_le < ?1 LIMIT ?2
     )`,
  ).bind(limite, LIMITES.purgeLot);
  let total = 0;
  for (;;) {
    const { meta } = await suppression.run();
    total += meta.changes;
    if (meta.changes < LIMITES.purgeLot) break;
  }
  return { supprimes: total, avant: limite };
}

// Reprise unique R2 -> D1. Copie seulement ; R2 n'est jamais modifié ni vidé.
// INSERT OR IGNORE + même id que dans R2 : relancer la reprise ne crée aucun doublon.
async function repriseCommentaires(env, executer) {
  const anciens = await anciensCommentairesR2(env);
  const valides = anciens.filter(commentaireR2Valide);
  const limite = dateLimite(env);
  const aReprendre = valides.filter((c) => c.creeLe >= limite); // les trop vieux seraient purgés aussitôt
  // Une seule requête : la liste des id est passée en paramètre (texte JSON), lue par json_each.
  const { results: presents } = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM commentaires WHERE id IN (SELECT value FROM json_each(?1))',
  ).bind(JSON.stringify(aReprendre.map((c) => c.id))).all();
  const dejaDansD1 = presents[0].n;
  const bilan = {
    simulation: !executer,
    dansR2: anciens.length,
    invalides: anciens.length - valides.length,
    tropAnciens: valides.length - aReprendre.length,
    dejaDansD1,
    aCopier: aReprendre.length - dejaDansD1,
    copies: 0,
  };
  if (!executer || aReprendre.length === 0) return json(bilan);

  const insertion = env.DB.prepare(
    `INSERT OR IGNORE INTO commentaires (id, outil_id, texte, auteur, cree_le)
     VALUES (?1, ?2, ?3, ?4, ?5)`,
  );
  for (let i = 0; i < aReprendre.length; i += 50) {
    const lot = aReprendre.slice(i, i + 50).map((c) => insertion.bind(c.id, c.outilId, c.texte, c.auteur, c.creeLe));
    const resultats = await env.DB.batch(lot);
    for (const r of resultats) bilan.copies += r.meta.changes;
  }
  return json(bilan);
}

// ---------- Routes ----------

async function lireTout(env) {
  const limite = dateLimite(env);
  const [clesFiches, anciens, { results: lignes }] = await Promise.all([
    listerCles(env.DATA, 'outils/'),
    anciensCommentairesR2(env),
    env.DB.prepare(
      'SELECT id, outil_id, texte, auteur, cree_le FROM commentaires WHERE cree_le >= ?1 ORDER BY cree_le',
    ).bind(limite).all(),
  ]);
  const fiches = await Promise.all(clesFiches.map((c) => lireJson(env.DATA, c)));
  const parFiche = {};
  for (const f of fiches) if (f) parFiche[f.donnees.outilId] = f.donnees;
  // D1 d'abord ; un ancien commentaire R2 déjà repris (même id) n'est pas compté deux fois.
  // Les anciens de R2 plus vieux que la durée de conservation ne sont plus affichés.
  const parOutil = {};
  const vus = new Set();
  for (const c of lignes.map(versCommentaire)) {
    vus.add(c.id);
    (parOutil[c.outilId] ||= []).push(c);
  }
  for (const c of anciens) {
    if (!commentaireR2Valide(c) || vus.has(c.id) || c.creeLe < limite) continue;
    vus.add(c.id);
    (parOutil[c.outilId] ||= []).push(c);
  }
  for (const liste of Object.values(parOutil)) liste.sort((a, b) => a.creeLe.localeCompare(b.creeLe));
  const turnstile = editionConfiguree(env) && etatTurnstile(env) === 'actif'
    ? { siteKey: env.TURNSTILE_SITE_KEY, action: actionTurnstile(env) }
    : null;
  return json({ editionActive: editionConfiguree(env), turnstile, fiches: parFiche, commentaires: parOutil });
}

async function initialiser(request, env, utilisateur) {
  const corps = await lireCorps(request);
  objetStrict(corps, 'corps', ['fiches']);
  if (!Array.isArray(corps.fiches)) throw new Invalide('fiches : liste attendue');
  if (corps.fiches.length > LIMITES.initNombre) throw new Invalide('fiches : trop nombreuses');

  // Tout valider avant d'écrire quoi que ce soit.
  const ids = new Set();
  const propres = corps.fiches.map((f, i) => {
    objetStrict(f, `fiches[${i}]`, ['outilId', 'champs', 'perso']);
    if (typeof f.outilId !== 'string' || !ID_OUTIL.test(f.outilId)) {
      throw new Invalide(`fiches[${i}].outilId invalide`);
    }
    if (ids.has(f.outilId)) throw new Invalide(`fiches[${i}].outilId en double`);
    ids.add(f.outilId);
    return { outilId: f.outilId, champs: validerChamps(f.champs), perso: validerPerso(f.perso ?? []) };
  });

  const maintenant = new Date().toISOString();
  const creees = [];
  const existantes = [];
  for (const f of propres) {
    const fiche = { ...f, version: 1, creeLe: maintenant, majLe: maintenant, majPar: utilisateur.email };
    // If-None-Match: * => R2 n'écrit que si l'objet n'existe pas encore. Jamais d'écrasement.
    const ecrit = await env.DATA.put(cleFiche(f.outilId), JSON.stringify(fiche), {
      onlyIf: new Headers({ 'if-none-match': '*' }),
      httpMetadata: { contentType: 'application/json' },
    });
    (ecrit ? creees : existantes).push(f.outilId);
  }
  return json({ creees, existantes });
}

async function modifier(request, env, utilisateur, id) {
  const corps = await lireCorps(request);
  objetStrict(corps, 'corps', ['version', 'champs', 'perso']);
  if (!Number.isInteger(corps.version) || corps.version < 1) throw new Invalide('version : entier attendu');
  const champs = validerChamps(corps.champs);
  const perso = validerPerso(corps.perso ?? []);

  const actuelle = await lireJson(env.DATA, cleFiche(id));
  if (!actuelle) return erreur(404, "Fiche absente : lancez d'abord l'initialisation.");
  if (actuelle.donnees.version !== corps.version) {
    return erreur(409, "Conflit : la fiche a été modifiée entre-temps. Rien n'a été écrasé.", {
      fiche: actuelle.donnees,
    });
  }
  const nouvelle = {
    ...actuelle.donnees,
    champs,
    perso,
    version: actuelle.donnees.version + 1,
    majLe: new Date().toISOString(),
    majPar: utilisateur.email,
  };
  // etagMatches => l'écriture échoue si quelqu'un a écrit entre la lecture et ici.
  const ecrit = await env.DATA.put(cleFiche(id), JSON.stringify(nouvelle), {
    onlyIf: { etagMatches: actuelle.etag },
    httpMetadata: { contentType: 'application/json' },
  });
  if (!ecrit) {
    const recente = await lireJson(env.DATA, cleFiche(id));
    return erreur(409, "Conflit : la fiche a été modifiée entre-temps. Rien n'a été écrasé.", {
      fiche: recente?.donnees ?? null,
    });
  }
  return json({ fiche: nouvelle });
}

async function commenter(request, env, utilisateur, id) {
  const corps = await lireCorps(request);
  objetStrict(corps, 'corps', ['texte']);
  const contenu = texte(corps.texte, 'texte', LIMITES.commentaire, { vide: false });
  if (!(await env.DATA.head(cleFiche(id)))) {
    return erreur(404, "Fiche absente : lancez d'abord l'initialisation.");
  }
  const commentaire = {
    id: crypto.randomUUID(),
    outilId: id,
    texte: contenu,
    auteur: utilisateur.email,
    creeLe: new Date().toISOString(),
  };
  await env.DB.prepare(
    'INSERT INTO commentaires (id, outil_id, texte, auteur, cree_le) VALUES (?1, ?2, ?3, ?4, ?5)',
  ).bind(commentaire.id, commentaire.outilId, commentaire.texte, commentaire.auteur, commentaire.creeLe).run();
  return json({ commentaire }, 201);
}

function retourSur(valeur) {
  // Seulement un chemin du même site : pas de redirection vers un autre domaine.
  return typeof valeur === 'string' && /^\/(?![/\\])[^\s]*$/.test(valeur) ? valeur : '/outils.html';
}

export async function traiter(request, env) {
  const { pathname, searchParams } = new URL(request.url);
  const methode = request.method;

  if (pathname === '/api/outils') {
    if (methode !== 'GET') return erreur(405, 'Méthode non autorisée.');
    return lireTout(env);
  }

  const lecture = pathname.match(/^\/api\/outils\/([^/]+)\/commentaires$/);
  if (lecture) {
    if (methode !== 'GET') return erreur(405, 'Méthode non autorisée.');
    if (!ID_OUTIL.test(lecture[1])) return erreur(400, 'Identifiant d’outil invalide.');
    return listerCommentaires(env, lecture[1], searchParams.get('avant'));
  }

  if (!pathname.startsWith('/api/edit/')) return erreur(404, 'Introuvable.');

  if (methode !== 'GET' && !origineAutorisee(request, env)) return erreur(403, 'Origine refusée.');
  const { utilisateur, reponse } = await exigerUtilisateur(request, env);
  if (reponse) return reponse;

  if (pathname === '/api/edit/session' && methode === 'GET') {
    return json({ email: utilisateur.email });
  }
  if (pathname === '/api/edit/connexion' && methode === 'GET') {
    return new Response(null, { status: 303, headers: { location: retourSur(searchParams.get('retour')) } });
  }
  if (pathname === '/api/edit/init' && methode === 'POST') {
    return initialiser(request, env, utilisateur);
  }
  if (pathname === '/api/edit/reprise-commentaires' && (methode === 'GET' || methode === 'POST')) {
    return repriseCommentaires(env, methode === 'POST');
  }
  const m = pathname.match(/^\/api\/edit\/outils\/([^/]+)(\/commentaires)?$/);
  if (m) {
    const id = m[1];
    if (!ID_OUTIL.test(id)) return erreur(400, 'Identifiant d’outil invalide.');
    if ((!m[2] && methode === 'PUT') || (m[2] && methode === 'POST')) {
      const refus = await verifierTurnstile(request, env);
      if (refus) return erreur(403, refus);
      return m[2] ? commenter(request, env, utilisateur, id) : modifier(request, env, utilisateur, id);
    }
  }
  return erreur(404, 'Introuvable.');
}

export default {
  async fetch(request, env) {
    try {
      return await traiter(request, env);
    } catch (e) {
      if (e instanceof Invalide) return erreur(400, e.message);
      return erreur(500, 'Erreur interne.');
    }
  },

  // Appelée chaque jour par Cloudflare (wrangler.jsonc > triggers.crons).
  async scheduled(controleur, env) {
    const r = await purgerCommentaires(env, new Date(controleur.scheduledTime));
    console.log(`Purge : ${r.supprimes} commentaire(s) antérieur(s) au ${r.avant} supprimé(s) de D1.`);
  },
};
