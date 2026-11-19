// Applique les migrations de migrations/*.sql à la base D1 simulée de Miniflare,
// dans l'ordre, comme le fait « wrangler d1 migrations apply ».
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const DOSSIER = fileURLToPath(new URL('../migrations/', import.meta.url));

export async function appliquerMigrations(mf) {
  const db = await mf.getD1Database('DB');
  const fichiers = (await readdir(DOSSIER)).filter((f) => f.endsWith('.sql')).sort();
  for (const f of fichiers) {
    const sql = (await readFile(join(DOSSIER, f), 'utf8'))
      .split('\n').map((l) => l.replace(/--.*$/, '')).join('\n');
    for (const instruction of sql.split(';').map((s) => s.trim()).filter(Boolean)) {
      await db.prepare(instruction).run();
    }
  }
  return db;
}
