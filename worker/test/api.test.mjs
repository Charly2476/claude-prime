// Tests de l'API (Worker exécuté en local dans Miniflare, avec un R2 et une base D1 simulés en mémoire).
// Les jetons Cloudflare Access sont signés par une clé RSA générée pour le test :
// aucun secret réel n'est utilisé.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto as crypto, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';
import { appliquerMigrations } from './d1.mjs';

const EQUIPE = 'equipe-test.cloudflareaccess.com';
const AUD = 'a1b2c3d4'.repeat(8);
const SITE = 'https://claude-prime-test.pages.dev';
const SCRIPT = fileURLToPath(new URL('../index.js', import.meta.url));

let mf, mfSansAccess, mfTurnstile, mfDemiTurnstile, mfD1, cle, autreCle;

const b64url = (buf) => Buffer.from(buf).toString('base64url');

async function genererCle(kid) {
  const paire = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );
  const jwk = await crypto.subtle.exportKey('jwk', paire.publicKey);
  return { kid, privee: paire.privateKey, jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e, kid, alg: 'RS256' } };
}

async function jeton({ email = 'charles@example.test', aud = AUD, iss = `https://${EQUIPE}`, exp, avec = cle } = {}) {
  const maintenant = Math.floor(Date.now() / 1000);
  const entete = b64url(JSON.stringify({ alg: 'RS256', kid: avec.kid, typ: 'JWT' }));
  const charge = b64url(JSON.stringify({ aud: [aud], iss, email, iat: maintenant, nbf: maintenant, exp: exp ?? maintenant + 3600 }));
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', avec.privee, new TextEncoder().encode(`${entete}.${charge}`));
  return `${entete}.${charge}.${b64url(signature)}`;
}

function creerMiniflare(bindings) {
  return new Miniflare({
    modules: true,
    scriptPath: SCRIPT,
    compatibilityDate: '2026-07-01',
    r2Buckets: ['DATA'],
    d1Databases: ['DB'],
    bindings,
    // Remplace l'appel réseau vers les certificats Access par la clé publique de test.
    outboundService: async (requete) => {
      if (requete.url === `https://${EQUIPE}/cdn-cgi/access/certs`) {
        return new Response(JSON.stringify({ keys: [cle.jwk] }), { headers: { 'content-type': 'application/json' } });
      }
      // Faux service Turnstile : le jeton décrit la réponse voulue.
      if (requete.url === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
        const f = await requete.formData();
        if (f.get('secret') !== 'secret-de-test') return Response.json({ success: false });
        const reponses = {
          bon: { success: true, action: 'soumission', hostname: 'claude-prime-c6r.pages.dev' },
          'mauvaise-action': { success: true, action: 'autre', hostname: 'claude-prime-c6r.pages.dev' },
          'mauvais-site': { success: true, action: 'soumission', hostname: 'evil.test' },
        };
        return Response.json(reponses[f.get('response')] ?? { success: false });
      }
      return new Response('bloqué', { status: 599 });
    },
  });
}

async function appel(methode, chemin, { corps, auth = true, entetes = {}, instance = mf } = {}) {
  const headers = { ...entetes };
  if (auth === true) headers['cf-access-jwt-assertion'] = await jeton();
  else if (typeof auth === 'string') headers['cf-access-jwt-assertion'] = auth;
  if (corps !== undefined && !('content-type' in headers)) headers['content-type'] = 'application/json';
  const r = await instance.dispatchFetch(SITE + chemin, {
    method: methode,
    headers,
    body: corps === undefined ? undefined : typeof corps === 'string' ? corps : JSON.stringify(corps),
    redirect: 'manual',
  });
  const texte = await r.text();
  let d = null;
  try { d = JSON.parse(texte); } catch { /* pas du JSON */ }
  return { statut: r.status, d, entetes: r.headers };
}

const ficheBase = (outilId, nom, url) => ({
  outilId,
  champs: {
    section: 'code', nom, mention: '', url, format: 'CLI', usage: `Usage de ${nom}`,
    acces: null, verifieLe: '2026-09-18', lienInteret: null,
  },
  perso: [],
});

const A = 'outil-001';
const B = 'outil-002';

before(async () => {
  cle = await genererCle('cle-test');
  autreCle = await genererCle('cle-test'); // même kid, autre clé : signature invalide
  mf = creerMiniflare({ ACCESS_TEAM_DOMAIN: EQUIPE, ACCESS_AUD: AUD });
  mfSansAccess = creerMiniflare({});
  const prod = {
    ACCESS_TEAM_DOMAIN: EQUIPE, ACCESS_AUD: AUD,
    ALLOWED_ORIGIN: 'https://claude-prime-c6r.pages.dev',
    TURNSTILE_HOSTNAME: 'claude-prime-c6r.pages.dev', TURNSTILE_ACTION: 'soumission',
    TURNSTILE_SITE_KEY: 'cle-publique-de-test',
  };
  mfTurnstile = creerMiniflare({ ...prod, TURNSTILE_SECRET_KEY: 'secret-de-test' });
  mfDemiTurnstile = creerMiniflare(prod); // clé publique sans secret
  mfD1 = creerMiniflare({ ACCESS_TEAM_DOMAIN: EQUIPE, ACCESS_AUD: AUD, DUREE_CONSERVATION_MOIS: '12' });
  for (const m of [mf, mfSansAccess, mfTurnstile, mfDemiTurnstile, mfD1]) await appliquerMigrations(m);
});

after(async () => {
  await mf.dispose();
  await mfSansAccess.dispose();
  await mfTurnstile.dispose();
  await mfDemiTurnstile.dispose();
  await mfD1.dispose();
});

test('sans protection configurée : lecture OK, édition désactivée (503)', async () => {
  const lecture = await appel('GET', '/api/outils', { instance: mfSansAccess, auth: false });
  assert.equal(lecture.statut, 200);
  assert.equal(lecture.d.editionActive, false);
  for (const [m, c, corps] of [
    ['POST', '/api/edit/init', { fiches: [] }],
    ['PUT', `/api/edit/outils/${A}`, { version: 1, champs: ficheBase(A, 'A', 'https://a.test').champs, perso: [] }],
    ['POST', `/api/edit/outils/${A}/commentaires`, { texte: 'x' }],
  ]) {
    const r = await appel(m, c, { corps, instance: mfSansAccess });
    assert.equal(r.statut, 503, `${m} ${c}`);
  }
});

test('accès non autorisé refusé : sans jeton, mauvaise signature, mauvaise audience, expiré, mauvais émetteur', async () => {
  const corps = { fiches: [ficheBase(A, 'A', 'https://a.test')] };
  const maintenant = Math.floor(Date.now() / 1000);
  const cas = {
    'sans jeton': false,
    'jeton bidon': 'abc.def.ghi',
    'mauvaise signature': await jeton({ avec: autreCle }),
    'mauvaise audience': await jeton({ aud: 'f'.repeat(64) }),
    'expiré': await jeton({ exp: maintenant - 10 }),
    'mauvais émetteur': await jeton({ iss: 'https://autre.cloudflareaccess.com' }),
    'sans e-mail': await jeton({ email: null }),
  };
  for (const [nom, auth] of Object.entries(cas)) {
    const r = await appel('POST', '/api/edit/init', { corps, auth });
    assert.equal(r.statut, 401, nom);
  }
  const session = await appel('GET', '/api/edit/session', { auth: false });
  assert.equal(session.statut, 401);
  // Rien n'a été écrit.
  const lecture = await appel('GET', '/api/outils', { auth: false });
  assert.deepEqual(lecture.d.fiches, {});
});

test('session et connexion : renvoie l’e-mail, redirection seulement vers le même site', async () => {
  const s = await appel('GET', '/api/edit/session');
  assert.equal(s.statut, 200);
  assert.equal(s.d.email, 'charles@example.test');
  const ok = await appel('GET', '/api/edit/connexion?retour=/outils.html');
  assert.equal(ok.statut, 303);
  assert.equal(ok.entetes.get('location'), '/outils.html');
  for (const piege of ['//evil.test/x', 'https://evil.test', '/\\evil.test']) {
    const r = await appel('GET', `/api/edit/connexion?retour=${encodeURIComponent(piege)}`);
    assert.equal(r.entetes.get('location'), '/outils.html', piege);
  }
});

test('initialisation : crée les fiches absentes, puis ne les écrase jamais', async () => {
  const r1 = await appel('POST', '/api/edit/init', {
    corps: { fiches: [ficheBase(A, 'Outil A', 'https://a.test'), ficheBase(B, 'Outil B', 'https://b.test')] },
  });
  assert.equal(r1.statut, 200);
  assert.deepEqual(r1.d.creees.sort(), [A, B]);

  // On modifie A, puis on relance l'initialisation avec l'ancienne liste.
  const lecture = await appel('GET', '/api/outils', { auth: false });
  const a = lecture.d.fiches[A];
  const maj = await appel('PUT', `/api/edit/outils/${A}`, {
    corps: { version: a.version, champs: { ...a.champs, usage: 'Usage modifié' }, perso: [] },
  });
  assert.equal(maj.statut, 200);

  const r2 = await appel('POST', '/api/edit/init', {
    corps: { fiches: [ficheBase(A, 'Outil A', 'https://a.test'), ficheBase(B, 'Outil B', 'https://b.test')] },
  });
  assert.equal(r2.statut, 200);
  assert.deepEqual(r2.d.creees, []);
  assert.deepEqual(r2.d.existantes.sort(), [A, B]);
  const apres = await appel('GET', '/api/outils', { auth: false });
  assert.equal(apres.d.fiches[A].champs.usage, 'Usage modifié');
  assert.equal(apres.d.fiches[A].version, 2);
});

test('modifier chaque champ et des champs personnalisés typés, puis relire', async () => {
  const avant = (await appel('GET', '/api/outils', { auth: false })).d.fiches[A];
  const champs = {
    section: 'inspiration',
    nom: 'Outil A renommé',
    mention: '(Exemple)',
    url: 'https://a-nouveau.test/page?x=1',
    format: 'Web',
    usage: 'Nouvel usage <b>pas du HTML</b>',
    acces: 'Gratuit',
    verifieLe: '2026-11-17',
    lienInteret: 'Aucun, vérifié',
  };
  const perso = [
    { cle: 'Open source', type: 'booleen', valeur: true },
    { cle: 'Payant', type: 'booleen', valeur: false },
    { cle: 'Testé le', type: 'date', valeur: '2026-11-01' },
    { cle: 'Date inconnue', type: 'date', valeur: null },
    { cle: 'Langages', type: 'liste', valeur: ['JS', 'TS', 'Python'] },
    { cle: 'Note', type: 'texte', valeur: 'à revoir' },
    { cle: 'Docs', type: 'url', valeur: 'http://docs.a.test' },
  ];
  const r = await appel('PUT', `/api/edit/outils/${A}`, { corps: { version: avant.version, champs, perso } });
  assert.equal(r.statut, 200);
  assert.equal(r.d.fiche.version, avant.version + 1);
  assert.equal(r.d.fiche.majPar, 'charles@example.test');

  // « Recharger » : nouvelle lecture complète.
  const relue = (await appel('GET', '/api/outils', { auth: false })).d.fiches[A];
  assert.deepEqual(relue.champs, champs);
  assert.deepEqual(relue.perso, perso);
  assert.equal(typeof relue.perso[0].valeur, 'boolean');
  assert.ok(Array.isArray(relue.perso[4].valeur));
  assert.equal(relue.outilId, A);

  // Remettre des valeurs vides possibles (null) fonctionne aussi.
  const vide = await appel('PUT', `/api/edit/outils/${A}`, {
    corps: { version: relue.version, champs: { ...champs, format: null, acces: null, verifieLe: null, lienInteret: null, mention: '' }, perso: [] },
  });
  assert.equal(vide.statut, 200);
  assert.equal(vide.d.fiche.champs.verifieLe, null);
});

test('commenter A sans toucher B', async () => {
  const avant = (await appel('GET', '/api/outils', { auth: false })).d;
  const r1 = await appel('POST', `/api/edit/outils/${A}/commentaires`, { corps: { texte: 'Premier sur A <script>alert(1)</script>' } });
  const r2 = await appel('POST', `/api/edit/outils/${A}/commentaires`, { corps: { texte: 'Deuxième sur A' } });
  assert.equal(r1.statut, 201);
  assert.equal(r2.statut, 201);
  assert.equal(r1.d.commentaire.auteur, 'charles@example.test');
  const apres = (await appel('GET', '/api/outils', { auth: false })).d;
  assert.deepEqual(apres.commentaires[A].map((c) => c.texte), ['Premier sur A <script>alert(1)</script>', 'Deuxième sur A']);
  assert.equal(apres.commentaires[B], undefined);
  assert.deepEqual(apres.fiches[B], avant.fiches[B]);
  assert.deepEqual(apres.fiches[A], avant.fiches[A]); // un commentaire ne change pas la fiche
});

test("changer l'URL de A sans perdre ses commentaires", async () => {
  const a = (await appel('GET', '/api/outils', { auth: false })).d.fiches[A];
  const r = await appel('PUT', `/api/edit/outils/${A}`, {
    corps: { version: a.version, champs: { ...a.champs, url: 'https://ailleurs.test/' }, perso: a.perso },
  });
  assert.equal(r.statut, 200);
  const d = (await appel('GET', '/api/outils', { auth: false })).d;
  assert.equal(d.fiches[A].champs.url, 'https://ailleurs.test/');
  assert.equal(d.commentaires[A].length, 2);
});

test('conflit de version : signalé (409), rien écrasé', async () => {
  const a = (await appel('GET', '/api/outils', { auth: false })).d.fiches[A];
  const ok = await appel('PUT', `/api/edit/outils/${A}`, { corps: { version: a.version, champs: { ...a.champs, usage: 'Version de Léa' }, perso: [] } });
  assert.equal(ok.statut, 200);
  const conflit = await appel('PUT', `/api/edit/outils/${A}`, { corps: { version: a.version, champs: { ...a.champs, usage: 'Version de Tom' }, perso: [] } });
  assert.equal(conflit.statut, 409);
  assert.equal(conflit.d.fiche.champs.usage, 'Version de Léa');
  const relue = (await appel('GET', '/api/outils', { auth: false })).d.fiches[A];
  assert.equal(relue.champs.usage, 'Version de Léa');
});

test('conflit simultané : deux écritures en même temps, une seule passe', async () => {
  const b = (await appel('GET', '/api/outils', { auth: false })).d.fiches[B];
  const envois = await Promise.all(
    ['un', 'deux', 'trois', 'quatre'].map((n) =>
      appel('PUT', `/api/edit/outils/${B}`, { corps: { version: b.version, champs: { ...b.champs, usage: n }, perso: [] } }),
    ),
  );
  const statuts = envois.map((e) => e.statut).sort();
  assert.equal(statuts.filter((s) => s === 200).length, 1, statuts.join(','));
  assert.ok(statuts.every((s) => s === 200 || s === 409));
  const relue = (await appel('GET', '/api/outils', { auth: false })).d.fiches[B];
  assert.equal(relue.version, b.version + 1);
});

test('envois invalides refusés (400/403/404), rien écrit', async () => {
  const a = (await appel('GET', '/api/outils', { auth: false })).d.fiches[A];
  const base = { version: a.version, champs: a.champs, perso: [] };
  const cas = [
    ['URL javascript:', { ...base, champs: { ...a.champs, url: 'javascript:alert(1)' } }],
    ['URL ftp', { ...base, champs: { ...a.champs, url: 'ftp://a.test' } }],
    ['URL sans schéma', { ...base, champs: { ...a.champs, url: 'a.test' } }],
    ['nom vide', { ...base, champs: { ...a.champs, nom: '   ' } }],
    ['nom trop long', { ...base, champs: { ...a.champs, nom: 'x'.repeat(121) } }],
    ['usage trop long', { ...base, champs: { ...a.champs, usage: 'x'.repeat(1001) } }],
    ['section inconnue', { ...base, champs: { ...a.champs, section: 'autre' } }],
    ['date impossible', { ...base, champs: { ...a.champs, verifieLe: '2026-02-30' } }],
    ['date mal formée', { ...base, champs: { ...a.champs, verifieLe: '17/11/2026' } }],
    ['champ inconnu', { ...base, champs: { ...a.champs, pirate: 1 } }],
    ['champ manquant', { ...base, champs: { ...a.champs, usage: undefined } }],
    ['format non texte', { ...base, champs: { ...a.champs, format: 42 } }],
    ['booléen en texte', { ...base, perso: [{ cle: 'x', type: 'booleen', valeur: 'true' }] }],
    ['liste en texte', { ...base, perso: [{ cle: 'x', type: 'liste', valeur: 'a,b' }] }],
    ['url perso invalide', { ...base, perso: [{ cle: 'x', type: 'url', valeur: 'data:text/html,hi' }] }],
    ['type perso inconnu', { ...base, perso: [{ cle: 'x', type: 'html', valeur: '<b>' }] }],
    ['clé perso en double', { ...base, perso: [{ cle: 'x', type: 'texte', valeur: '1' }, { cle: 'X', type: 'texte', valeur: '2' }] }],
    ['trop de champs perso', { ...base, perso: Array.from({ length: 21 }, (_, i) => ({ cle: `c${i}`, type: 'texte', valeur: '' })) }],
    ['version absente', { champs: a.champs, perso: [] }],
  ];
  for (const [nom, corps] of cas) {
    const r = await appel('PUT', `/api/edit/outils/${A}`, { corps: JSON.parse(JSON.stringify(corps)) });
    assert.equal(r.statut, 400, `${nom} → ${r.statut} ${JSON.stringify(r.d)}`);
  }
  assert.equal((await appel('PUT', `/api/edit/outils/${A}`, { corps: 'pas du json' })).statut, 400);
  assert.equal((await appel('PUT', `/api/edit/outils/${A}`, { corps: base, entetes: { 'content-type': 'text/plain' } })).statut, 400);
  assert.equal((await appel('PUT', `/api/edit/outils/${A}`, { corps: { ...base, champs: { ...a.champs, usage: 'x'.repeat(70000) } } })).statut, 400);
  assert.equal((await appel('PUT', `/api/edit/outils/${A}`, { corps: base, entetes: { origin: 'https://evil.test' } })).statut, 403);
  assert.equal((await appel('PUT', '/api/edit/outils/..%2Fpirate', { corps: base })).statut, 400);
  assert.equal((await appel('PUT', '/api/edit/outils/outil-999', { corps: base })).statut, 404);
  assert.equal((await appel('POST', `/api/edit/outils/${A}/commentaires`, { corps: { texte: '' } })).statut, 400);
  assert.equal((await appel('POST', `/api/edit/outils/${A}/commentaires`, { corps: { texte: 'x'.repeat(2001) } })).statut, 400);
  assert.equal((await appel('POST', '/api/edit/outils/outil-999/commentaires', { corps: { texte: 'x' } })).statut, 404);
  assert.equal((await appel('POST', '/api/edit/init', { corps: { fiches: [{ ...ficheBase('mauvais id', 'X', 'https://x.test') }] } })).statut, 400);

  const relue = (await appel('GET', '/api/outils', { auth: false })).d;
  assert.deepEqual(relue.fiches[A], a);
  assert.equal(relue.commentaires[A].length, 2);
});

test('stockage : fiches dans R2 (outils/), nouveaux commentaires dans D1 seulement', async () => {
  const cles = (await (await mf.getR2Bucket('DATA')).list()).objects.map((o) => o.key);
  assert.deepEqual(cles.sort(), ['outils/outil-001.json', 'outils/outil-002.json']);
  const db = await mf.getD1Database('DB');
  const { results } = await db.prepare('SELECT outil_id, texte, auteur FROM commentaires ORDER BY cree_le').all();
  assert.deepEqual(results.map((l) => l.outil_id), [A, A]);
  assert.equal(results[1].texte, 'Deuxième sur A');
  assert.equal(results[0].auteur, 'charles@example.test');
});

test('Turnstile à moitié réglé (clé publique sans secret) : édition désactivée', async () => {
  const lecture = await appel('GET', '/api/outils', { instance: mfDemiTurnstile, auth: false });
  assert.equal(lecture.d.editionActive, false);
  assert.equal(lecture.d.turnstile, null);
  const r = await appel('POST', '/api/edit/init', { corps: { fiches: [] }, instance: mfDemiTurnstile });
  assert.equal(r.statut, 503);
});

test('ALLOWED_ORIGIN et Turnstile : en plus de Access, pas à la place', async () => {
  const site = { origin: 'https://claude-prime-c6r.pages.dev' };
  const lecture = await appel('GET', '/api/outils', { instance: mfTurnstile, auth: false });
  assert.deepEqual(lecture.d.turnstile, { siteKey: 'cle-publique-de-test', action: 'soumission' });

  const init = await appel('POST', '/api/edit/init', {
    instance: mfTurnstile, entetes: site, corps: { fiches: [ficheBase(A, 'Outil A', 'https://a.test')] },
  });
  assert.equal(init.statut, 200);
  const fiche = (await appel('GET', '/api/outils', { instance: mfTurnstile, auth: false })).d.fiches[A];
  const corps = { version: fiche.version, champs: { ...fiche.champs, usage: 'via Turnstile' }, perso: [] };
  const put = (entetes, auth = true) => appel('PUT', `/api/edit/outils/${A}`, { instance: mfTurnstile, corps, entetes, auth });

  assert.equal((await put({ ...site, origin: SITE, 'cf-turnstile-response': 'bon' })).statut, 403, 'autre origine');
  assert.equal((await put(site)).statut, 403, 'sans jeton Turnstile');
  for (const t of ['faux', 'mauvaise-action', 'mauvais-site']) {
    assert.equal((await put({ ...site, 'cf-turnstile-response': t })).statut, 403, t);
  }
  assert.equal((await put({ ...site, 'cf-turnstile-response': 'bon' }, false)).statut, 401, 'Turnstile seul ne suffit pas');
  assert.equal((await appel('POST', `/api/edit/outils/${A}/commentaires`, { instance: mfTurnstile, entetes: site, corps: { texte: 'x' } })).statut, 403);

  assert.equal((await put({ ...site, 'cf-turnstile-response': 'bon' })).statut, 200);
  const com = await appel('POST', `/api/edit/outils/${A}/commentaires`, {
    instance: mfTurnstile, entetes: { ...site, 'cf-turnstile-response': 'bon' }, corps: { texte: 'ok' },
  });
  assert.equal(com.statut, 201);
  const relue = (await appel('GET', '/api/outils', { instance: mfTurnstile, auth: false })).d;
  assert.equal(relue.fiches[A].champs.usage, 'via Turnstile');
  assert.equal(relue.fiches[A].version, 2);
  assert.equal(relue.commentaires[A].length, 1);
});

// ---------- D1 : pagination, requêtes paramétrées, purge, reprise ----------

const ilYa = (mois, jours = 0) => {
  const d = new Date();
  d.setUTCMonth(d.getUTCMonth() - mois);
  d.setUTCDate(d.getUTCDate() - jours);
  return d.toISOString();
};

async function insererD1(instance, lignes) {
  const db = await instance.getD1Database('DB');
  const ins = db.prepare('INSERT INTO commentaires (id, outil_id, texte, auteur, cree_le) VALUES (?1, ?2, ?3, ?4, ?5)');
  await db.batch(lignes.map((l) => ins.bind(l.id ?? randomUUID(), l.outilId, l.texte, l.auteur ?? 'x@example.test', l.creeLe)));
  return db;
}

test('GET /api/outils/:id/commentaires : 20 derniers, puis pages suivantes, sans trou ni doublon', async () => {
  const base = Date.parse('2026-11-01T10:00:00.000Z');
  const lignes = Array.from({ length: 45 }, (_, i) => ({
    outilId: 'outil-010',
    texte: `c${i}`,
    // Deux commentaires par seconde : teste le départage par id quand la date est identique.
    creeLe: new Date(base + Math.floor(i / 2) * 1000).toISOString(),
  }));
  lignes.push({ outilId: 'outil-011', texte: 'autre outil', creeLe: new Date(base + 999999).toISOString() });
  await insererD1(mfD1, lignes);

  const vus = [];
  let curseur = null;
  const tailles = [];
  do {
    const r = await appel('GET', `/api/outils/outil-010/commentaires${curseur ? `?avant=${curseur}` : ''}`, { instance: mfD1, auth: false });
    assert.equal(r.statut, 200);
    tailles.push(r.d.commentaires.length);
    vus.push(...r.d.commentaires);
    curseur = r.d.suivant;
  } while (curseur);
  assert.deepEqual(tailles, [20, 20, 5]);
  assert.equal(new Set(vus.map((c) => c.id)).size, 45);
  assert.ok(vus.every((c) => c.outilId === 'outil-010'));
  // Du plus récent au plus ancien.
  for (let i = 1; i < vus.length; i++) assert.ok(vus[i - 1].creeLe >= vus[i].creeLe);
  assert.equal(vus[0].creeLe, lignes[44].creeLe);
  assert.deepEqual(Object.keys(vus[0]).sort(), ['auteur', 'creeLe', 'id', 'outilId', 'texte']);

  const vide = await appel('GET', '/api/outils/outil-012/commentaires', { instance: mfD1, auth: false });
  assert.deepEqual(vide.d, { outilId: 'outil-012', commentaires: [], suivant: null });
  assert.equal((await appel('GET', '/api/outils/outil-010/commentaires?avant=nimporte', { instance: mfD1, auth: false })).statut, 400);
  assert.equal((await appel('GET', '/api/outils/pas-un-id/commentaires', { instance: mfD1, auth: false })).statut, 400);
  assert.equal((await appel('POST', '/api/outils/outil-010/commentaires', { instance: mfD1, auth: false, corps: { texte: 'x' } })).statut, 405);
});

test('requêtes paramétrées : un texte « SQL » est stocké tel quel, la table reste intacte', async () => {
  await appel('POST', '/api/edit/init', { instance: mfD1, corps: { fiches: [ficheBase('outil-020', 'Outil 20', 'https://o20.test')] } });
  const piege = "'); DROP TABLE commentaires; -- \" OR 1=1 ?1 $1";
  const r = await appel('POST', '/api/edit/outils/outil-020/commentaires', { instance: mfD1, corps: { texte: piege } });
  assert.equal(r.statut, 201);
  const lu = await appel('GET', '/api/outils/outil-020/commentaires', { instance: mfD1, auth: false });
  assert.equal(lu.d.commentaires[0].texte, piege);
  const page10 = await appel('GET', '/api/outils/outil-010/commentaires', { instance: mfD1, auth: false });
  assert.equal(page10.d.commentaires.length, 20);

  // Contrôle du code : aucune valeur insérée dans le texte SQL (pas de ${...} ni de + dans prepare()).
  const code = await readFile(SCRIPT, 'utf8');
  const prepares = [...code.matchAll(/\.prepare\(\s*([`'"])([\s\S]*?)\1\s*,?\s*\)/g)];
  assert.ok(prepares.length >= 6, `requêtes trouvées : ${prepares.length}`);
  for (const [, , sql] of prepares) assert.ok(!sql.includes('${'), sql);
  assert.equal((code.match(/\.prepare\(/g) || []).length, prepares.length, 'prepare() avec un texte non littéral');
});

test('tâche planifiée : supprime les commentaires de plus de 12 mois, garde les autres, ne touche pas R2', async () => {
  const vieux = randomUUID();
  const recent = randomUUID();
  const db = await insererD1(mfD1, [
    { id: vieux, outilId: 'outil-030', texte: 'vieux', creeLe: ilYa(12, 2) },
    { id: recent, outilId: 'outil-030', texte: 'récent', creeLe: ilYa(11, 20) },
  ]);
  const r2Avant = (await (await mfD1.getR2Bucket('DATA')).list()).objects.length;
  const avant = (await db.prepare('SELECT COUNT(*) AS n FROM commentaires').first()).n;

  const worker = await mfD1.getWorker();
  await worker.scheduled({ scheduledTime: new Date(), cron: '17 3 * * *' });

  assert.equal(await db.prepare('SELECT id FROM commentaires WHERE id = ?1').bind(vieux).first(), null);
  assert.ok(await db.prepare('SELECT id FROM commentaires WHERE id = ?1').bind(recent).first());
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM commentaires').first()).n, avant - 1);
  assert.equal((await (await mfD1.getR2Bucket('DATA')).list()).objects.length, r2Avant);
});

test('reprise R2 -> D1 : simulation sans écriture, puis copie unique, sans doublon, R2 intact', async () => {
  const bucket = await mfD1.getR2Bucket('DATA');
  await appel('POST', '/api/edit/init', { instance: mfD1, corps: { fiches: [ficheBase('outil-040', 'Outil 40', 'https://o40.test')] } });
  const ancien = (texte, creeLe, extra = {}) => ({ id: randomUUID(), outilId: 'outil-040', texte, auteur: 'ancien@example.test', creeLe, ...extra });
  const anciens = [
    ancien('ancien 1', ilYa(2)),
    ancien('ancien 2', ilYa(1)),
    ancien('trop vieux', ilYa(13)),
    ancien('', ilYa(1)), // invalide : texte vide
  ];
  const dejaRepris = ancien('déjà dans D1', ilYa(3));
  anciens.push(dejaRepris);
  for (const c of anciens) await bucket.put(`commentaires/outil-040/${c.id}.json`, JSON.stringify(c));
  await insererD1(mfD1, [dejaRepris]);
  const clesR2 = async () => (await bucket.list({ prefix: 'commentaires/' })).objects.map((o) => o.key).sort();
  const r2Avant = await clesR2();

  // Avant la reprise, la page voit déjà les anciens (lus dans R2), sans doublon ni trop vieux.
  const vue = async () => (await appel('GET', '/api/outils', { instance: mfD1, auth: false })).d.commentaires['outil-040'].map((c) => c.texte).sort();
  assert.deepEqual(await vue(), ['ancien 1', 'ancien 2', 'déjà dans D1']);

  assert.equal((await appel('GET', '/api/edit/reprise-commentaires', { instance: mfD1, auth: false })).statut, 401);
  const simulation = await appel('GET', '/api/edit/reprise-commentaires', { instance: mfD1 });
  assert.deepEqual(simulation.d, { simulation: true, dansR2: 5, invalides: 1, tropAnciens: 1, dejaDansD1: 1, aCopier: 2, copies: 0 });
  const lire040 = async () => (await appel('GET', '/api/outils/outil-040/commentaires', { instance: mfD1, auth: false })).d.commentaires;
  assert.equal((await lire040()).length, 1, 'la simulation n’écrit rien');

  const reprise = await appel('POST', '/api/edit/reprise-commentaires', { instance: mfD1 });
  assert.equal(reprise.statut, 200);
  assert.equal(reprise.d.copies, 2);
  const relance = await appel('POST', '/api/edit/reprise-commentaires', { instance: mfD1 });
  assert.equal(relance.d.copies, 0);
  assert.equal(relance.d.dejaDansD1, 3);

  const d1 = await lire040();
  assert.deepEqual(d1.map((c) => c.texte), ['ancien 2', 'ancien 1', 'déjà dans D1']);
  assert.equal(d1.find((c) => c.texte === 'ancien 1').auteur, 'ancien@example.test');
  assert.deepEqual(await vue(), ['ancien 1', 'ancien 2', 'déjà dans D1']);
  assert.deepEqual(await clesR2(), r2Avant, 'rien supprimé ni modifié dans R2');
  assert.equal((await appel('POST', '/api/edit/reprise-commentaires', { instance: mfD1, entetes: { origin: 'https://evil.test' } })).statut, 403);
});
