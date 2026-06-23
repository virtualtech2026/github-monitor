require("dotenv").config();
const axios = require("axios");
const pool = require("./db");
const sendTelegram = require("./telegram");

// ======================================================
// CONFIG
// ======================================================

const CONFIG = {
  ALERT_THRESHOLD: 60,
  MIN_IOC_TYPES: 3,
  MAX_FILE_SIZE: 800000,
  BASE_SLEEP: 2500,
  REQUEST_TIMEOUT: 15000,

  RATE_LIMIT_BACKOFF: 60000,
  MAX_RETRIES: 4,

  REPO_CACHE_TTL: 1000 * 60 * 60 // 1 hour
};

// ======================================================
// LOGGER (structured logging)
// ======================================================

function log(type, data) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    type,
    ...data
  }));
}

// ======================================================
// IOC ENGINE (FIXED + CLASSIFIED + WEIGHTED)
// ======================================================

const IOC_RULES = [
  // HIGH CONFIDENCE: backend + infra
  { type: "backend_endpoint", weight: 20, pattern: /appjs-2ff5fe395d54\.herokuapp\.com/i },

  { type: "contract_address", weight: 25, pattern: /0x[a-fA-F0-9]{40}/ },

  // FUNCTION IOCs (strict boundary match)
  { type: "handler_function", weight: 18, pattern: /\b(sendMessHandler|addApproveHandler|addSeaHandler|getSellSeaMessage)\b/ },

  { type: "ui_binding", weight: 10, pattern: /\b(connectElement|messageElement|twoStepButtonElement)\b/ },

  { type: "seaport_logic", weight: 15, pattern: /\b(Seaport|OrderComponents|OfferItem|ConsiderationItem)\b/ },

  { type: "api_route", weight: 12, pattern: /balances_v2\/\?quote-currency=ETH/i },

  { type: "signature_flow", weight: 14, pattern: /eth_signTypedData_v4/i },

  // UI assets
  { type: "asset", weight: 6, pattern: /\blogo[1-4]\.png\b/i },

  // misc identifiers
  { type: "campaign_token", weight: 12, pattern: /\b(scanSea|scanNoeth|seanfts|compareWorth|actionSea)\b/ }
];

// classify IOC hits
function extractIOCs(content) {
  const hits = [];
  const types = new Set();

  for (const rule of IOC_RULES) {
    const match = content.match(rule.pattern);
    if (match) {
      hits.push({
        type: rule.type,
        weight: rule.weight,
        matches: [...new Set(match.map(m => m.trim()))]
      });
      types.add(rule.type);
    }
  }

  return { hits, types: Array.from(types) };
}

// weighted scoring
function computeScore(iocs) {
  let score = 0;

  for (const i of iocs) {
    score += i.weight * Math.min(i.matches.length, 3);
  }

  // normalization curve (0–100)
  return Math.min(100, Math.round(score));
}

// ======================================================
// GITHUB CLIENT (rate-limit safe + retry + backoff)
// ======================================================

async function githubRequest(url, attempt = 0) {
  try {
    return await axios.get(url, {
      timeout: CONFIG.REQUEST_TIMEOUT,
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        "User-Agent": "ioc-intelligence-engine"
      }
    });
  } catch (e) {
    const status = e?.response?.status;

    if (status === 403 || status === 429) {
      const wait = CONFIG.RATE_LIMIT_BACKOFF * (attempt + 1);
      log("rate_limit", { wait });
      await new Promise(r => setTimeout(r, wait));
      if (attempt < CONFIG.MAX_RETRIES) {
        return githubRequest(url, attempt + 1);
      }
    }

    return null;
  }
}

// search
async function searchGitHub(query, page = 1) {
  const url =
    `https://api.github.com/search/code?q=${encodeURIComponent(query)}+in:file&per_page=30&page=${page}`;

  const res = await githubRequest(url);
  return res?.data?.items || [];
}

// fetch raw file
async function fetchFile(item) {
  const url = item.html_url
    .replace("github.com", "raw.githubusercontent.com")
    .replace("/blob/", "/");

  const res = await githubRequest(url);
  return res?.data || null;
}

// ======================================================
// REPO AGGREGATOR (graph-style accumulation)
// ======================================================

const repoState = new Map();
const seenFiles = new Set();
const seenRepos = new Map();

function updateRepo(repo, iocResult) {
  if (!repoState.has(repo)) {
    repoState.set(repo, {
      score: 0,
      types: new Set(),
      iocs: [],
      files: 0
    });
  }

  const r = repoState.get(repo);

  r.files += 1;
  r.iocs.push(...iocResult.hits);

  for (const t of iocResult.types) {
    r.types.add(t);
  }

  r.score += computeScore(iocResult.hits);
}

// ======================================================
// ALERT ENGINE (strict filtering)
// ======================================================

function shouldAlert(repo) {
  const r = repoState.get(repo);

  if (!r) return false;

  const score = r.score;
  const typeCount = r.types.size;

  return score >= CONFIG.ALERT_THRESHOLD &&
         typeCount >= CONFIG.MIN_IOC_TYPES;
}

// dedupe key stronger than before
function buildAlertKey(repo, score, types) {
  return `${repo}:${Math.floor(score / 10)}:${types.sort().join(",")}`;
}

// ======================================================
// PROCESSING PIPELINE
// ======================================================

const BASE_QUERIES = [
  "connect wallet",
  "Seaport OrderComponents",
  "balances_v2",
  "eth_signTypedData_v4",
  "sendMessHandler",
  "compareWorth"
];

async function processQuery(query) {
  const results = await searchGitHub(query);

  for (const item of results) {
    const repo = item.repository.full_name;
    const fileKey = `${repo}:${item.path}`;

    if (seenFiles.has(fileKey)) continue;
    seenFiles.add(fileKey);

    const content = await fetchFile(item);
    if (!content) continue;

    const iocResult = extractIOCs(content);

    if (iocResult.hits.length === 0) continue;

    updateRepo(repo, iocResult);
  }
}

// ======================================================
// EVALUATOR
// ======================================================

async function evaluate() {
  for (const [repo, data] of repoState.entries()) {

    if (!shouldAlert(repo)) continue;

    const scoreBand = Math.floor(data.score / 10);
    const alertKey = buildAlertKey(repo, data.score, Array.from(data.types));

    if (seenRepos.has(alertKey)) continue;
    seenRepos.set(alertKey, Date.now());

    const repoUrl = `https://github.com/${repo}`;

    log("alert", {
      repo,
      score: data.score,
      types: Array.from(data.types),
      files: data.files
    });

    await pool.query(
      `INSERT INTO findings (keyword, repo_name, file_path, html_url, score, severity)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT DO NOTHING`,
      ["ioc-intel-v2", repo, null, repoUrl, data.score, "IOC_MATCH"]
    );

    await sendTelegram(
`🚨 INTELLIGENCE CARD

Repo: ${repo}
${repoUrl}

Score: ${data.score}/100
Signal Types: ${Array.from(data.types).join(", ")}

Files: ${data.files}

Confidence: ${data.score > 80 ? "HIGH" : "MEDIUM"}`
    );
  }
}

// ======================================================
// WORKER
// ======================================================

async function cycle() {
  log("cycle_start", {});

  repoState.clear();
  seenFiles.clear();

  let page = 1;

  for (const q of BASE_QUERIES) {
    await processQuery(q, page);
    page = page % 3 + 1; // light pagination drift
  }

  await evaluate();

  log("cycle_complete", {});
}

async function start() {
  log("system_start", {});

  while (true) {
    try {
      await cycle();
      await new Promise(r => setTimeout(r, 5 * 60 * 1000));
    } catch (e) {
      log("worker_error", { error: e.message });
      await new Promise(r => setTimeout(r, 5000));
    }
  }
}

start();
