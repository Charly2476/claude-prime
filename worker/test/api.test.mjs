// Tests de l'API (Worker exécuté en local dans Miniflare, avec un R2 simulé en mémoire).
// Les jetons Cloudflare Access sont signés par une clé RSA générée pour le test :
// aucun secret réel n'est utilisé.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto as crypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';

const EQUIPE = 'equipe-test.cloudflareaccess.com';
const AUD = 'a1b2c3d4'.repeat(8);
const SITE = 'https://claude-prime-test.pages.dev';
const SCRIPT = fileURLToPath(new URL('../index.js', import.meta.url));

let mf, mfSansAccess, mfTurnstile, mfDemiTurnstile, cle, autreCle;

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
});

after(async () => {
  await mf.dispose();
  await mfSansAccess.dispose();
  await mfTurnstile.dispose();
  await mfDemiTurnstile.dispose();
});

test('sans protection configurée : lecture OK, édition désactivée (503)', async () => {
  const lecture = await appel('GET', '/api/outils', { instance: mfSansAccess, auth: false });
  assert.equal(lecture.statut, 200);
  assert.equal(lecture.d.editionActive, false);
  for (const [m, c, corps] of [
    ['POST', '/api/edit/init', { fiches: [] }],
    ['PUT', `/api/outils/${A}`, { version: 1, champs: ficheBase(A, 'A', 'https://a.test').champs, perso: [] }],
    ['POST', `/api/outils/${A}/commentaires`, { texte: 'x' }],
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
  const maj = await appel('PUT', `/api/outils/${A}`, {
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
  const r = await appel('PUT', `/api/outils/${A}`, { corps: { version: avant.version, champs, perso } });
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
  const vide = await appel('PUT', `/api/outils/${A}`, {
    corps: { version: relue.version, champs: { ...champs, format: null, acces: null, verifieLe: null, lienInteret: null, mention: '' }, perso: [] },
  });
  assert.equal(vide.statut, 200);
  assert.equal(vide.d.fiche.champs.verifieLe, null);
});

test('commenter A sans toucher B', async () => {
  const avant = (await appel('GET', '/api/outils', { auth: false })).d;
  const r1 = await appel('POST', `/api/outils/${A}/commentaires`, { corps: { texte: 'Premier sur A <script>alert(1)</script>' } });
  const r2 = await appel('POST', `/api/outils/${A}/commentaires`, { corps: { texte: 'Deuxième sur A' } });
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
  const r = await appel('PUT', `/api/outils/${A}`, {
    corps: { version: a.version, champs: { ...a.champs, url: 'https://ailleurs.test/' }, perso: a.perso },
  });
  assert.equal(r.statut, 200);
  const d = (await appel('GET', '/api/outils', { auth: false })).d;
  assert.equal(d.fiches[A].champs.url, 'https://ailleurs.test/');
  assert.equal(d.commentaires[A].length, 2);
});

test('conflit de version : signalé (409), rien écrasé', async () => {
  const a = (await appel('GET', '/api/outils', { auth: false })).d.fiches[A];
  const ok = await appel('PUT', `/api/outils/${A}`, { corps: { version: a.version, champs: { ...a.champs, usage: 'Version de Léa' }, perso: [] } });
  assert.equal(ok.statut, 200);
  const conflit = await appel('PUT', `/api/outils/${A}`, { corps: { version: a.version, champs: { ...a.champs, usage: 'Version de Tom' }, perso: [] } });
  assert.equal(conflit.statut, 409);
  assert.equal(conflit.d.fiche.champs.usage, 'Version de Léa');
  const relue = (await appel('GET', '/api/outils', { auth: false })).d.fiches[A];
  assert.equal(relue.champs.usage, 'Version de Léa');
});

test('conflit simultané : deux écritures en même temps, une seule passe', async () => {
  const b = (await appel('GET', '/api/outils', { auth: false })).d.fiches[B];
  const envois = await Promise.all(
    ['un', 'deux', 'trois', 'quatre'].map((n) =>
      appel('PUT', `/api/outils/${B}`, { corps: { version: b.version, champs: { ...b.champs, usage: n }, perso: [] } }),
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
    const r = await appel('PUT', `/api/outils/${A}`, { corps: JSON.parse(JSON.stringify(corps)) });
    assert.equal(r.statut, 400, `${nom} → ${r.statut} ${JSON.stringify(r.d)}`);
  }
  assert.equal((await appel('PUT', `/api/outils/${A}`, { corps: 'pas du json' })).statut, 400);
  assert.equal((await appel('PUT', `/api/outils/${A}`, { corps: base, entetes: { 'content-type': 'text/plain' } })).statut, 400);
  assert.equal((await appel('PUT', `/api/outils/${A}`, { corps: { ...base, champs: { ...a.champs, usage: 'x'.repeat(70000) } } })).statut, 400);
  assert.equal((await appel('PUT', `/api/outils/${A}`, { corps: base, entetes: { origin: 'https://evil.test' } })).statut, 403);
  assert.equal((await appel('PUT', '/api/outils/..%2Fpirate', { corps: base })).statut, 400);
  assert.equal((await appel('PUT', '/api/outils/outil-999', { corps: base })).statut, 404);
  assert.equal((await appel('POST', `/api/outils/${A}/commentaires`, { corps: { texte: '' } })).statut, 400);
  assert.equal((await appel('POST', `/api/outils/${A}/commentaires`, { corps: { texte: 'x'.repeat(2001) } })).statut, 400);
  assert.equal((await appel('POST', '/api/outils/outil-999/commentaires', { corps: { texte: 'x' } })).statut, 404);
  assert.equal((await appel('POST', '/api/edit/init', { corps: { fiches: [{ ...ficheBase('mauvais id', 'X', 'https://x.test') }] } })).statut, 400);

  const relue = (await appel('GET', '/api/outils', { auth: false })).d;
  assert.deepEqual(relue.fiches[A], a);
  assert.equal(relue.commentaires[A].length, 2);
});

test('R2 : une fiche par outil dans outils/, un objet par commentaire dans commentaires/<outilId>/', async () => {
  const cles = (await (await mf.getR2Bucket('DATA')).list()).objects.map((o) => o.key);
  assert.ok(cles.includes('outils/outil-001.json'));
  assert.ok(cles.includes('outils/outil-002.json'));
  const coms = cles.filter((c) => c.startsWith('commentaires/'));
  assert.equal(coms.length, 2);
  for (const c of coms) assert.match(c, /^commentaires\/outil-001\/[0-9a-f-]{36}\.json$/);
  assert.equal(cles.length, 4);
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
  const put = (entetes, auth = true) => appel('PUT', `/api/outils/${A}`, { instance: mfTurnstile, corps, entetes, auth });

  assert.equal((await put({ ...site, origin: SITE, 'cf-turnstile-response': 'bon' })).statut, 403, 'autre origine');
  assert.equal((await put(site)).statut, 403, 'sans jeton Turnstile');
  for (const t of ['faux', 'mauvaise-action', 'mauvais-site']) {
    assert.equal((await put({ ...site, 'cf-turnstile-response': t })).statut, 403, t);
  }
  assert.equal((await put({ ...site, 'cf-turnstile-response': 'bon' }, false)).statut, 401, 'Turnstile seul ne suffit pas');
  assert.equal((await appel('POST', `/api/outils/${A}/commentaires`, { instance: mfTurnstile, entetes: site, corps: { texte: 'x' } })).statut, 403);

  assert.equal((await put({ ...site, 'cf-turnstile-response': 'bon' })).statut, 200);
  const com = await appel('POST', `/api/outils/${A}/commentaires`, {
    instance: mfTurnstile, entetes: { ...site, 'cf-turnstile-response': 'bon' }, corps: { texte: 'ok' },
  });
  assert.equal(com.statut, 201);
  const relue = (await appel('GET', '/api/outils', { instance: mfTurnstile, auth: false })).d;
  assert.equal(relue.fiches[A].champs.usage, 'via Turnstile');
  assert.equal(relue.fiches[A].version, 2);
  assert.equal(relue.commentaires[A].length, 1);
});

test('routes des consignes : GET des commentaires d’un outil (public)', async () => {
  const r = await appel('GET', `/api/outils/${A}/commentaires`, { auth: false });
  assert.equal(r.statut, 200);
  assert.equal(r.d.outilId, A);
  assert.deepEqual(r.d.commentaires.map((c) => c.texte), ['Premier sur A <script>alert(1)</script>', 'Deuxième sur A']);
  const b = await appel('GET', `/api/outils/${B}/commentaires`, { auth: false });
  assert.deepEqual(b.d.commentaires, []);
  assert.equal((await appel('GET', '/api/outils/outil-999/commentaires', { auth: false })).statut, 404);
  assert.equal((await appel('GET', '/api/outils/..%2Foutils/commentaires', { auth: false })).statut, 400);
});

test('routes des consignes : écriture avec le cookie CF_Authorization seul', async () => {
  const a = (await appel('GET', '/api/outils', { auth: false })).d.fiches[A];
  const corps = { version: a.version, champs: { ...a.champs, usage: 'via cookie' }, perso: a.perso };
  const r = await appel('PUT', `/api/outils/${A}`, { corps, auth: false, entetes: { cookie: `autre=1; CF_Authorization=${await jeton()}` } });
  assert.equal(r.statut, 200);
  const c = await appel('POST', `/api/outils/${A}/commentaires`, {
    corps: { texte: 'commentaire via cookie' }, auth: false, entetes: { cookie: `CF_Authorization=${await jeton()}` },
  });
  assert.equal(c.statut, 201);
  const faux = await appel('PUT', `/api/outils/${A}`, { corps, auth: false, entetes: { cookie: 'CF_Authorization=abc.def.ghi' } });
  assert.equal(faux.statut, 401);
});

test('routes des consignes : méthodes non prévues refusées, anciennes routes absentes', async () => {
  const a = (await appel('GET', '/api/outils', { auth: false })).d.fiches[A];
  const corps = { version: a.version, champs: a.champs, perso: [] };
  assert.equal((await appel('POST', '/api/outils', { corps })).statut, 405);
  assert.equal((await appel('GET', `/api/outils/${A}`, { auth: false })).statut, 405);
  assert.equal((await appel('DELETE', `/api/outils/${A}`)).statut, 405);
  assert.equal((await appel('PUT', `/api/outils/${A}/commentaires`, { corps })).statut, 405);
  assert.equal((await appel('PUT', `/api/edit/outils/${A}`, { corps })).statut, 404);
  assert.equal((await appel('POST', '/api/soumissions', { corps: {} })).statut, 404);
  assert.equal((await appel('PUT', `/api/outils/${A}`, { corps, auth: false })).statut, 401);
  assert.equal((await appel('POST', `/api/outils/${A}/commentaires`, { corps: { texte: 'x' }, auth: false })).statut, 401);
});
