// Cloudflare Pages : transmet /api/* au Worker claude-prime-api (liaison de service « API »).
// La page et l'API restent ainsi sur le même domaine, ce qui permet à Cloudflare Access
// de protéger /api/edit/* avec son cookie de connexion. Rien d'autre n'est fait ici :
// toute la vérification (jeton Access, validation, versions) est dans worker/index.js.
export async function onRequest({ request, env }) {
  if (!env.API) {
    return new Response(JSON.stringify({ erreur: 'API non reliée (liaison de service API absente).' }), {
      status: 503,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    });
  }
  return env.API.fetch(request);
}
