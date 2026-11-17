// claude-prime-api : enregistre les fiches et les commentaires de outils.html dans R2.
//
// Stockage R2 (liaison DATA) :
//   outils/<outilId>.json               une fiche par outil (avec "version"), ex. outils/outil-001.json
//   commentaires/<outilId>/<uuid>.json  un objet par commentaire
//
// Routes (la page les appelle sur son propre domaine, via functions/api/[[path]].js) :
//   GET  /api/outils                          lecture publique des fiches et commentaires
//   GET  /api/edit/session                    qui est connecté (protégé)
//   GET  /api/edit/connexion?retour=/...      passe par Cloudflare Access puis revient (protégé)
//   POST /api/edit/init                       crée les fiches absentes, n'écrase jamais (protégé)
//   PUT  /api/edit/outils/:id                 modifie une fiche, contrôle de version (protégé)
//   POST /api/edit/outils/:id/commentaires    ajoute un commentaire (protégé)
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
const prefixeCommentaires = (id) => `commentaires/${id}/`;

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

// ---------- Routes ----------

async function lireTout(env) {
  const [clesFiches, clesCommentaires] = await Promise.all([
    listerCles(env.DATA, 'outils/'),
    listerCles(env.DATA, 'commentaires/'),
  ]);
  const [fiches, commentaires] = await Promise.all([
    Promise.all(clesFiches.map((c) => lireJson(env.DATA, c))),
    Promise.all(clesCommentaires.map((c) => lireJson(env.DATA, c))),
  ]);
  const parFiche = {};
  for (const f of fiches) if (f) parFiche[f.donnees.outilId] = f.donnees;
  const parOutil = {};
  for (const c of commentaires) {
    if (!c) continue;
    (parOutil[c.donnees.outilId] ||= []).push(c.donnees);
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
  const creeLe = new Date().toISOString();
  const commentaireId = crypto.randomUUID();
  const commentaire = { id: commentaireId, outilId: id, texte: contenu, auteur: utilisateur.email, creeLe };
  await env.DATA.put(`${prefixeCommentaires(id)}${commentaireId}.json`, JSON.stringify(commentaire), {
    onlyIf: new Headers({ 'if-none-match': '*' }),
    httpMetadata: { contentType: 'application/json' },
  });
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
};
