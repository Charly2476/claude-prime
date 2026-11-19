// Test de bout en bout de outils.html dans Chromium (Playwright).
// Reproduit en local le montage de production :
//   - un petit serveur sert les fichiers du dépôt (comme Cloudflare Pages) ;
//   - /api/* est transmis au Worker dans Miniflare (comme functions/api/[[path]].js) ;
//   - Cloudflare Access est simulé en ajoutant l'en-tête Cf-Access-Jwt-Assertion,
//     signé par une clé de test (aucun secret réel).
// Playwright n'est pas dans package.json : ce test l'utilise s'il est installé.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { webcrypto as crypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join, normalize } from 'node:path';
import { Miniflare } from 'miniflare';
import { appliquerMigrations } from './d1.mjs';

const require = createRequire(import.meta.url);
let chromium;
try { ({ chromium } = require('playwright')); } catch { /* absent */ }

const RACINE = fileURLToPath(new URL('../../', import.meta.url));
const SCRIPT = fileURLToPath(new URL('../index.js', import.meta.url));
const EQUIPE = 'equipe-test.cloudflareaccess.com';
const AUD = 'a1b2c3d4'.repeat(8);
const b64url = (b) => Buffer.from(b).toString('base64url');

let cle, mf, mfSansAccess, serveur, serveurSansAccess, navigateur;

async function jeton(email = 'charles@example.test') {
  const t = Math.floor(Date.now() / 1000);
  const h = b64url(JSON.stringify({ alg: 'RS256', kid: 'k1' }));
  const p = b64url(JSON.stringify({ aud: [AUD], iss: `https://${EQUIPE}`, email, iat: t, nbf: t, exp: t + 3600 }));
  const s = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cle.privateKey, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(s)}`;
}

function miniflare(bindings, jwk) {
  return new Miniflare({
    modules: true, scriptPath: SCRIPT, compatibilityDate: '2026-07-01', r2Buckets: ['DATA'], d1Databases: ['DB'], bindings,
    outboundService: (r) => r.url.endsWith('/cdn-cgi/access/certs')
      ? new Response(JSON.stringify({ keys: [jwk] }))
      : new Response('bloqué', { status: 599 }),
  });
}

function demarrerSite(instance) {
  const s = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      const morceaux = [];
      for await (const m of req) morceaux.push(m);
      const corps = Buffer.concat(morceaux);
      const r = await instance.dispatchFetch(`http://${req.headers.host}${req.url}`, {
        method: req.method,
        headers: req.headers,
        body: corps.length ? corps : undefined,
        redirect: 'manual',
      });
      res.writeHead(r.status, Object.fromEntries(r.headers));
      res.end(Buffer.from(await r.arrayBuffer()));
      return;
    }
    const chemin = normalize(join(RACINE, url.pathname === '/' ? 'index.html' : url.pathname));
    if (!chemin.startsWith(RACINE)) { res.writeHead(403).end(); return; }
    try {
      const contenu = await readFile(chemin);
      res.writeHead(200, { 'content-type': chemin.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/plain' });
      res.end(contenu);
    } catch { res.writeHead(404).end(); }
  });
  return new Promise((ok) => s.listen(0, '127.0.0.1', () => ok(s)));
}

const adresse = (s) => `http://127.0.0.1:${s.address().port}`;

async function page({ connecte = true, site = serveur } = {}) {
  const contexte = await navigateur.newContext({
    extraHTTPHeaders: connecte ? { 'cf-access-jwt-assertion': await jeton() } : {},
  });
  const p = await contexte.newPage();
  const erreursJs = [];
  p.on('pageerror', (e) => erreursJs.push(e.message));
  p.on('dialog', (d) => d.accept()); // confirme « Initialiser »
  await p.goto(`${adresse(site)}/outils.html`);
  await p.waitForFunction(() => !document.getElementById('etat-edition').textContent.includes('Chargement'));
  return { p, contexte, erreursJs };
}

const ligne = (p, nom) => p.locator('tr[data-outil-id]').filter({ has: p.locator(`td:first-child >> text="${nom}"`) }).first();

before(async () => {
  if (!chromium) return;
  cle = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  );
  const pub = await crypto.subtle.exportKey('jwk', cle.publicKey);
  const jwk = { kty: pub.kty, n: pub.n, e: pub.e, kid: 'k1', alg: 'RS256' };
  mf = miniflare({ ACCESS_TEAM_DOMAIN: EQUIPE, ACCESS_AUD: AUD }, jwk);
  mfSansAccess = miniflare({}, jwk);
  await appliquerMigrations(mf);
  await appliquerMigrations(mfSansAccess);
  serveur = await demarrerSite(mf);
  serveurSansAccess = await demarrerSite(mfSansAccess);
  navigateur = await chromium.launch();
});

after(async () => {
  if (!chromium) return;
  await navigateur.close();
  serveur.close();
  serveurSansAccess.close();
  await mf.dispose();
  await mfSansAccess.dispose();
});

test('parcours complet dans le navigateur', { skip: !chromium && 'Playwright absent' }, async (t) => {
  await t.test('fichier ouvert sans API : liste intacte, lecture seule', async () => {
    const contexte = await navigateur.newContext();
    const p = await contexte.newPage();
    await p.goto('file://' + join(RACINE, 'outils.html'));
    await p.waitForFunction(() => document.getElementById('etat-edition').textContent.includes('Lecture seule'));
    assert.equal(await p.locator('tr[data-outil-id]').count(), 69);
    assert.equal(await p.locator('.actions button:disabled').count(), 138);
    assert.equal(await p.locator('nav.toc a').count(), 8);
    assert.equal(await ligne(p, 'Aider').locator('td').nth(1).textContent(), 'CLI');
    await contexte.close();
  });

  await t.test('protection non configurée : modification désactivée', async () => {
    const { p, contexte } = await page({ site: serveurSansAccess });
    assert.match(await p.locator('#etat-edition').textContent(), /modification désactivée/);
    assert.equal(await p.locator('.actions button:disabled').count(), 138);
    await contexte.close();
  });

  await t.test('non connecté : lien de connexion, boutons désactivés', async () => {
    const { p, contexte } = await page({ connecte: false });
    assert.equal(await p.locator('#etat-edition a').getAttribute('href'), '/api/edit/connexion?retour=%2Foutils.html');
    assert.equal(await p.locator('.actions button:disabled').count(), 138);
    await contexte.close();
  });

  await t.test('initialisation unique depuis la liste', async () => {
    const { p, contexte, erreursJs } = await page();
    await p.getByRole('button', { name: /Initialiser 69 fiche/ }).click();
    await p.waitForFunction(() => document.getElementById('etat-edition').textContent.includes('69 créée(s)'));
    assert.equal(await p.locator('.actions button:disabled').count(), 0);
    assert.deepEqual(erreursJs, []);
    await contexte.close();
  });

  await t.test('formulaire prérempli avec tous les champs', async () => {
    const { p, contexte } = await page();
    await ligne(p, 'Playwright MCP').getByRole('button', { name: 'Modifier la fiche' }).click();
    const f = p.locator('#form-fiche');
    assert.equal(await f.locator('[name=section]').inputValue(), 'tests');
    assert.equal(await f.locator('[name=nom]').inputValue(), 'Playwright MCP');
    assert.equal(await f.locator('[name=mention]').inputValue(), '(Microsoft)');
    assert.equal(await f.locator('[name=url]').inputValue(), 'https://github.com/microsoft/playwright-mcp');
    assert.equal(await f.locator('[name=format]').inputValue(), 'MCP');
    assert.equal(await f.locator('[name=usage]').inputValue(), 'Automatisation de navigateur par snapshots structurés');
    assert.equal(await f.locator('[name=acces]').inputValue(), 'Client Apache-2.0 ; conditions du modèle séparées');
    assert.equal(await f.locator('[name=verifieLe]').inputValue(), '2026-09-18');
    assert.equal(await f.locator('[name=lienInteret]').inputValue(), '');
    await contexte.close();
  });

  await t.test('modifier chaque champ + champs personnalisés, recharger, rouvrir', async () => {
    const { p, contexte } = await page();
    await ligne(p, 'Aider').getByRole('button', { name: 'Modifier la fiche' }).click();
    const f = p.locator('#form-fiche');
    await f.locator('[name=section]').selectOption('deploiement');
    await f.locator('[name=nom]').fill('Aider modifié');
    await f.locator('[name=mention]').fill('(test)');
    await f.locator('[name=url]').fill('https://aider.example.test/');
    await f.locator('[name=format]').fill('Web');
    await f.locator('[name=usage]').fill('<img src=x onerror="window.pirate=1">');
    await f.locator('[name=acces]').fill('Gratuit');
    await f.locator('[name=verifieLe]').fill('2026-11-17');
    await f.locator('[name=lienInteret]').fill('Aucun');
    const ajouter = async (cle, type, remplir) => {
      await p.locator('#perso-ajouter').click();
      const l = p.locator('#perso-liste .perso-ligne').last();
      await l.locator('[data-role=cle]').fill(cle);
      await l.locator('[data-role=type]').selectOption(type);
      await remplir(l.locator('[data-role=valeur]'));
    };
    await ajouter('Open source', 'booleen', (v) => v.check());
    await ajouter('Langages', 'liste', (v) => v.fill('JS\nPython'));
    await ajouter('Testé le', 'date', (v) => v.fill('2026-11-01'));
    await ajouter('Docs', 'url', (v) => v.fill('https://docs.example.test'));
    await ajouter('Note', 'texte', (v) => v.fill('ok'));
    await f.getByRole('button', { name: 'Enregistrer' }).click();
    await p.locator('#dlg-fiche').waitFor({ state: 'hidden' });

    await p.reload();
    await p.waitForFunction(() => document.getElementById('etat-edition').textContent.includes('Connecté'));
    const l = ligne(p, 'Aider modifié');
    assert.equal(await l.evaluate((tr) => tr.closest('.table-wrap').dataset.section), 'deploiement');
    const cellules = await l.locator(':scope > td').allTextContents();
    assert.match(cellules[0], /^Aider modifié \(test\)/);
    assert.equal(cellules[1], 'Web');
    assert.match(cellules[2], /^<img src=x onerror="window.pirate=1">/); // affiché comme texte
    assert.match(cellules[2], /Open source : Oui/);
    assert.match(cellules[2], /Langages : JS, Python/);
    assert.equal(cellules[3], 'Gratuit');
    assert.equal(cellules[4], '2026-11-17');
    assert.equal(cellules[5], 'Aucun');
    assert.equal(await l.locator('td a').first().getAttribute('href'), 'https://aider.example.test/');
    assert.equal(await l.locator('img').count(), 0);
    assert.equal(await p.evaluate(() => window.pirate), undefined);

    await l.getByRole('button', { name: 'Modifier la fiche' }).click();
    const lignes = p.locator('#perso-liste .perso-ligne');
    assert.equal(await lignes.count(), 5);
    assert.equal(await lignes.nth(0).locator('[data-role=type]').inputValue(), 'booleen');
    assert.equal(await lignes.nth(0).locator('[data-role=valeur]').isChecked(), true);
    assert.equal(await lignes.nth(1).locator('[data-role=valeur]').inputValue(), 'JS\nPython');
    assert.equal(await lignes.nth(2).locator('[data-role=valeur]').inputValue(), '2026-11-01');
    assert.equal(await f.locator('[name=section]').inputValue(), 'deploiement');
    await contexte.close();
  });

  await t.test('commenter A sans toucher B ; changer l’URL de A garde ses commentaires', async () => {
    const { p, contexte } = await page();
    await ligne(p, 'Cursor').getByRole('button', { name: 'Ajouter un commentaire' }).click();
    await p.locator('#form-commentaire [name=texte]').fill('<b>gras ?</b> commentaire de test');
    await p.locator('#form-commentaire').getByRole('button', { name: 'Publier' }).click();
    await p.locator('#dlg-commentaire').waitFor({ state: 'hidden' });
    const a = ligne(p, 'Cursor');
    assert.equal(await a.locator('details.commentaires summary').textContent(), '1 commentaire');
    assert.equal(await a.locator('.commentaire-texte').textContent(), '<b>gras ?</b> commentaire de test');
    assert.equal(await a.locator('.commentaire-texte b').count(), 0);
    assert.equal(await ligne(p, 'Kiro').locator('details.commentaires').count(), 0);

    await a.getByRole('button', { name: 'Modifier la fiche' }).click();
    await p.locator('#form-fiche [name=url]').fill('https://cursor.example.test/');
    await p.locator('#form-fiche').getByRole('button', { name: 'Enregistrer' }).click();
    await p.locator('#dlg-fiche').waitFor({ state: 'hidden' });
    await p.reload();
    await p.waitForFunction(() => document.getElementById('etat-edition').textContent.includes('Connecté'));
    const apres = ligne(p, 'Cursor');
    assert.equal(await apres.locator('td a').first().getAttribute('href'), 'https://cursor.example.test/');
    assert.equal(await apres.locator('details.commentaires summary').textContent(), '1 commentaire');
    await contexte.close();
  });

  await t.test('URL invalide refusée par le formulaire', async () => {
    const { p, contexte } = await page();
    let envois = 0;
    p.on('request', (r) => { if (r.method() === 'PUT') envois++; });
    await ligne(p, 'Kiro').getByRole('button', { name: 'Modifier la fiche' }).click();
    await p.locator('#form-fiche [name=url]').fill('javascript:alert(1)');
    await p.locator('#form-fiche').getByRole('button', { name: 'Enregistrer' }).click();
    assert.match(await p.locator('#fiche-erreur').textContent(), /URL http ou https/);
    assert.equal(envois, 0);
    await contexte.close();
  });

  await t.test('conflit : deux onglets, le second est prévenu et n’écrase rien', async () => {
    const un = await page();
    const deux = await page();
    for (const { p } of [un, deux]) {
      await ligne(p, 'Goose').getByRole('button', { name: 'Modifier la fiche' }).click();
      await p.locator('#form-fiche [name=usage]').fill(p === un.p ? 'Version onglet 1' : 'Version onglet 2');
    }
    await un.p.locator('#form-fiche').getByRole('button', { name: 'Enregistrer' }).click();
    await un.p.locator('#dlg-fiche').waitFor({ state: 'hidden' });
    await deux.p.locator('#form-fiche').getByRole('button', { name: 'Enregistrer' }).click();
    await deux.p.waitForFunction(() => document.getElementById('fiche-erreur').textContent.includes('Conflit'));
    assert.equal(await deux.p.locator('#dlg-fiche').isVisible(), true);
    assert.equal(await deux.p.locator('#form-fiche [name=usage]').inputValue(), 'Version onglet 2'); // saisie gardée
    const trois = await page();
    assert.equal(await ligne(trois.p, 'Goose').locator(':scope > td').nth(2).textContent(), 'Version onglet 1');
    for (const x of [un, deux, trois]) await x.contexte.close();
  });
});
