-- Migration 0001 : table des commentaires (base D1, liaison DB).
-- Appliquée par : npx wrangler d1 migrations apply projet-db --remote
-- Une migration déjà appliquée n'est jamais rejouée (wrangler la note dans la table d1_migrations).
-- Pour changer la table plus tard : créer 0002_....sql, ne jamais modifier ce fichier.

CREATE TABLE IF NOT EXISTS commentaires (
  id        TEXT PRIMARY KEY,  -- UUID, le même que dans R2 pour les commentaires repris (pas de doublon)
  outil_id  TEXT NOT NULL,     -- ex. outil-001 (la fiche reste dans R2 : outils/outil-001.json)
  texte     TEXT NOT NULL,
  auteur    TEXT NOT NULL,     -- e-mail donné par Cloudflare Access
  cree_le   TEXT NOT NULL      -- date ISO UTC, ex. 2026-11-19T20:12:00.000Z (se trie comme du texte)
);

-- Sert à lire les N derniers commentaires d'un outil (WHERE outil_id = ? ORDER BY cree_le DESC).
CREATE INDEX IF NOT EXISTS idx_commentaires_outil_date ON commentaires (outil_id, cree_le);
