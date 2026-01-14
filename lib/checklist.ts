import { checklistColumns, checklistRows } from "@/lib/checklist-data";

export type ChecklistColumn = (typeof checklistColumns)[number];
export type ChecklistRow = (typeof checklistRows)[number];

const columnById = new Map(checklistColumns.map((col) => [col.id, col]));
const HIDDEN_CHECKS = new Set([
  "internet_services_policy_v4",
  "ipsec_phase_2_op_basis_van_0_0_0_0_0_routes",
  "ssl_vpn_password_safe_off",
  "interface_alias_ingevuld",
  "standaard_objecten_aanwezig_v29",
]);

export function getColumnById(id: ChecklistColumn["id"]) {
  return columnById.get(id) ?? null;
}

export function getMetadataColumns() {
  return checklistColumns.filter((col) => !col.isCheck);
}

export function getCheckColumns() {
  return checklistColumns.filter((col) => col.isCheck && !HIDDEN_CHECKS.has(col.id));
}

export function getRows() {
  return checklistRows;
}

function normalizeMatch(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function extractHost(url: string) {
  const match = url.match(/https?:\/\/([^/:]+)/i);
  return match ? match[1] : "";
}

type Matcher = {
  token: string;
  normalized: string;
  weight: number;
};

const STOPWORDS = new Set([
  "bv",
  "b.v",
  "b.v.",
  "b",
  "stichting",
  "holding",
  "groep",
  "group",
  "zorg",
  "and",
  "de",
  "van",
  "voor",
  "the",
  "en",
  "cv",
  "fgt",
]);

function pushMatcher(list: Matcher[], token: string, weight: number) {
  const normalized = normalizeMatch(token);
  if (normalized.length < 3) return;
  if (isGenericToken(normalized)) return;
  list.push({ token, normalized, weight });
}

function isGenericToken(normalized: string) {
  if (normalized === "fgt" || normalized === "fg") return true;
  if (/^fgt\d+[a-z]?$/.test(normalized)) return true;
  if (/^fg\d+[a-z]?$/.test(normalized)) return true;
  return false;
}

export function buildMatchers(row: ChecklistRow) {
  const tokens: Matcher[] = [];
  const klant = row.values.klant ?? "";
  const adminUrl = row.values.admin_webinterface ?? "";

  const parenMatches = klant.match(/\(([^)]+)\)/g) ?? [];
  for (const match of parenMatches) {
    const token = match.replace(/[()]/g, "").trim();
    if (token) pushMatcher(tokens, token, 3);
  }

  const cleanedName = klant.replace(/\([^)]+\)/g, " ");
  const nameParts = cleanedName.split(/[^A-Za-z0-9]+/).filter(Boolean);
  for (const part of nameParts) {
    const lower = part.toLowerCase();
    if (STOPWORDS.has(lower)) continue;
    if (part.length < 4) continue;
    pushMatcher(tokens, part, 1);
  }

  const host = extractHost(adminUrl);
  if (host) {
    pushMatcher(tokens, host, 2);
    const parts = host.split(".");
    if (parts.length > 0) pushMatcher(tokens, parts[0], 1);
  }

  return tokens;
}

export function detectCustomerByFilename(filename: string) {
  const normalizedFilename = normalizeMatch(filename);
  const matches = checklistRows
    .map((row) => {
      const matchers = buildMatchers(row);
      let best: { token: string; score: number } | null = null;
      let totalScore = 0;
      for (const matcher of matchers) {
        if (!matcher.normalized) continue;
        if (normalizedFilename.includes(matcher.normalized)) {
          const score = matcher.normalized.length * matcher.weight;
          totalScore += score;
          if (!best || score > best.score) {
            best = { token: matcher.token, score };
          }
        }
      }
      return best ? { row, token: best.token, score: totalScore } : null;
    })
    .filter(Boolean) as { row: ChecklistRow; token: string; score: number }[];

  matches.sort((a, b) => b.score - a.score);
  return matches;
}
