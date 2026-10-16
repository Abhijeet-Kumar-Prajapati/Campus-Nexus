// ============================================================================
//  Arcade module  —  derived from the two C-language projects
//    Project 1 : number guessing  (1–100, higher/lower hints, attempt count)
//    Project 2 : snake · water · gun (computer picks via rand(), win/draw/lose)
//  Upgraded: difficulty levels, best-of-N rounds, scoring formulas,
//  persistent leaderboard shared by both games.
// ============================================================================
import { db, logActivity } from "../db.js";
import { fail, readJson } from "../http.js";

export const GAMES = {
  guess: { id: "guess", label: "Number Guessing", difficulty: true },
  swg: { id: "swg", label: "Snake · Water · Gun", difficulty: false },
};

const str = (v, max = 60) => String(v ?? "").trim().slice(0, max);
const num = (v, def = 0) => (Number.isFinite(Number(v)) ? Number(v) : def);

/* ---------------------------------------------------- scoring reference --- */
/** Number guessing: fewer attempts + smaller range = higher score. */
export function scoreGuess({ range, attempts, won }) {
  if (!won) return 0;
  const base = { 10: 120, 50: 100, 100: 80, 500: 55 }[range] ?? 80;
  const speedBonus = Math.max(0, Math.round(((range === 10 ? 3 : range === 50 ? 4 : range === 100 ? 6 : 9) - attempts) * 8));
  return Math.max(10, base + speedBonus);
}

/** Snake-Water-Gun: wins dominate, streak bonus, draws are half value. */
export function scoreSwg({ wins, losses, draws }) {
  return wins * 30 + draws * 8 - losses * 5 + (wins >= 3 ? 20 : 0);
}

export function leaderboard(game = "all", limit = 20) {
  const clause = GAMES[game] ? "WHERE game = ?" : "";
  const rows = db
    .prepare(
      `SELECT * FROM game_scores ${clause} ORDER BY score DESC, played_at ASC LIMIT ?`
    )
    .all(...(GAMES[game] ? [game] : []), limit);
  const out = [];
  for (const g of Object.keys(GAMES)) {
    const best = rows.find((r) => r.game === g);
    out.push({
      game: g,
      label: GAMES[g].label,
      topScore: best?.score ?? 0,
      topPlayer: best?.player ?? "—",
      plays: db.prepare("SELECT COUNT(*) n FROM game_scores WHERE game=?").get(g).n,
    });
  }
  return { entries: rows, summary: out };
}

export async function saveScore(req, res) {
  const b = await readJson(req);
  const game = str(b.game, 20);
  if (!GAMES[game]) return fail(res, "Unknown game");
  const player = str(b.player, 40);
  if (!player) return fail(res, "Player name is required");
  const score = Math.max(0, Math.min(9999, Math.round(num(b.score, 0))));
  if (score <= 0) return fail(res, "Score must be greater than 0");

  const detail = str(b.detail, 120);
  db.prepare("INSERT INTO game_scores (game, player, score, detail) VALUES (?,?,?,?)")
    .run(game, player, score, detail);
  logActivity("arcade", `${GAMES[game].label} score`, `${player} scored ${score}`);

  const rank = db
    .prepare(`SELECT COUNT(*) + 1 AS r FROM game_scores WHERE game=? AND score > ?`)
    .get(game, score).r;

  res.json({ ok: true, rank, message: `${player} — ${score} pts (rank #${rank} in ${GAMES[game].label})` }, 201);
}

export function arcadeStats() {
  const row = db
    .prepare(`SELECT COUNT(*) AS plays, COUNT(DISTINCT player) AS players FROM game_scores`)
    .get();
  return { plays: row.plays, players: row.players, games: Object.keys(GAMES).length };
}