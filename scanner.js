require("dotenv").config();

const axios = require("axios");
const pool = require("./db");
const sendTelegram = require("./telegram");

// =========================
// CONFIG
// =========================

const ALERT_THRESHOLD = 25;
const HIGH_CONFIDENCE_THRESHOLD = 35;

const MAX_FILE_SIZE = 800000;
const BASE_SLEEP = 5000;

const ALERT_COOLDOWN = 6 * 60 * 60 * 1000;

// =========================
// STATE
// =========================

const processedFiles = new Set();
const alertedRepos = new Map();

// 🔥 GLOBAL SAFE MODE (NEW FIX)
let globalCooldownUntil = 0;

// =========================
// GLOBAL REQUEST THROTTLE (CRITICAL FIX)
// =========================

let lastRequestTime = 0;
const MIN_INTERVAL = 2500; // ~24 req/min safe zone

async function throttleGitHub() {
  const now = Date.now();

  // global cooldown from 403
  if (now < globalCooldownUntil) {
    const wait = globalCooldownUntil - now;
    console.log(`🧊 Global cooldown active: waiting ${Math.round(wait/1000)}s`);
    await sleep(wait);
  }

  const diff = now - lastRequestTime;
  if (diff < MIN_INTERVAL) {
    await sleep(MIN_INTERVAL - diff);
  }

  lastRequestTime = Date.now();
}

// =========================
// HELPERS
// =========================

function buildRepoUrl(repoName) {
  return `https://github.com/${repoName}`;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// =========================
// BASE KEYWORDS (NO EXPANSION OVERLOAD)
// =========================

const BASE_KEYWORDS = [
  "wallet drainer",
  "crypto drainer",
  "seed phrase",
  "recovery phrase",
  "mnemonic phrase",
  "walletconnect phishing",
  "setApprovalForAll",
  "permit2",
  "personal_sign"
];

// =========================
// PATTERNS
// =========================

const SECRET_PATTERNS = [
  { name: "Seed Phrase", regex: /(seed phrase|recovery phrase|mnemonic)/gi, severity: "critical" },
  { name: "Wallet Input Theft", regex: /(enter|input|paste).{0,40}(seed|phrase)/gi, severity: "critical" },
  { name: "Approval Abuse", regex: /setApprovalForAll|increaseAllowance/gi, severity: "high" },
  { name: "Signature Abuse", regex: /eth_signTypedData|personal_sign/gi, severity: "medium" },
  { name: "Drain Logic", regex: /(drain wallet|sweep wallet|transfer all balance)/gi, severity: "critical" },
  { name: "Webhook Exfiltration", regex: /discord|telegram\.org\/bot|webhook/i, severity: "critical" }
];

// =========================
// BEHAVIOR PATTERNS
// =========================

const BEHAVIOR_PATTERNS = [
  { regex: /(approve|setApprovalForAll).{0,80}(transfer|drain|sweep)/gi, weight: 12 },
  { regex: /(sign|signature).{0,80}(claim|verify|reward|airdrop)/gi, weight: 10 },
  { regex: /(connect wallet).{0,50}(claim|mint|verify)/gi, weight: 9 },
  { regex: /(transferFrom|send max|drain wallet)/gi, weight: 15 }
];

// =========================
// NOISE FILTER
// =========================

function shouldSkipFile(item) {
  const path = (item.path || "").toLowerCase();

  return (
    path.endsWith(".md") ||
    path.includes("readme") ||
    path.includes("license") ||
    path.includes("/docs/") ||
    path.includes("/example/") ||
    path.includes(".map") ||
    path.includes("package-lock.json")
  );
}

// =========================
// SIGNAL ENGINE
// =========================

function extractSignals(content) {
  let signalScore = 0;
  let behaviorScore = 0;
  let legitPenalty = 0;

  for (const p of SECRET_PATTERNS) {
    if (p.regex.test(content)) signalScore += 1;
  }

  for (const b of BEHAVIOR_PATTERNS) {
    if (b.regex.test(content)) behaviorScore += b.weight;
  }

  return { signalScore, behaviorScore, legitPenalty };
}

// =========================
// REPO CACHE
// =========================

function updateRepo(repoName, data) {
  if (!global.repoCache) global.repoCache = new Map();

  const cache = global.repoCache;

  if (!cache.has(repoName)) {
    cache.set(repoName, {
      signalScore: 0,
      behaviorScore: 0,
      legitPenalty: 0,
      files: 0
    });
  }

  const repo = cache.get(repoName);

  repo.signalScore += data.signalScore;
  repo.behaviorScore += data.behaviorScore;
  repo.files += 1;
}

// =========================
// SCORE
// =========================

function computeRepoScore(repo) {
  return repo.signalScore + repo.behaviorScore * 1.5;
}

// =========================
// GITHUB SEARCH (STABLE + SAFE)
// =========================

async function searchKeyword(keyword) {
  const url =
    `https://api.github.com/search/code?q=${encodeURIComponent(keyword)}+in:file&per_page=30`;

  try {
    await throttleGitHub();

    const res = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        "User-Agent": "soc-scanner"
      }
    });

    return res.data?.items || [];
  } catch (err) {
    const status = err.response?.status;

    if (status === 403) {
      console.log("⚠️ 403 detected → entering 10 min global cooldown");

      globalCooldownUntil = Date.now() + 10 * 60 * 1000;

      return [];
    }

    console.error("Search error:", err.message);
    return [];
  }
}

// =========================
// FETCH FILE
// =========================

async function fetchFile(item) {
  try {
    const url = item.html_url
      .replace("github.com", "raw.githubusercontent.com")
      .replace("/blob/", "/");

    await throttleGitHub();

    const res = await axios.get(url, {
      maxContentLength: MAX_FILE_SIZE
    });

    return res.data;
  } catch {
    return null;
  }
}

// =========================
// PROCESS
// =========================

async function processKeyword(keyword) {
  const results = await searchKeyword(keyword);

  for (const item of results) {
    try {
      const repoName = item.repository.full_name;
      const fileKey = `${repoName}:${item.path}`;

      if (processedFiles.has(fileKey)) continue;
      processedFiles.add(fileKey);

      if (shouldSkipFile(item)) continue;

      const content = await fetchFile(item);
      if (!content) continue;

      const signals = extractSignals(content);

      updateRepo(repoName, signals);

    } catch (err) {
      console.error("Process error:", err.message);
    }
  }
}

// =========================
// ALERT ENGINE
// =========================

async function evaluateRepos() {
  const cache = global.repoCache || new Map();
  const now = Date.now();

  for (const [repoName, repo] of cache.entries()) {

    const score = computeRepoScore(repo);

    if (score < ALERT_THRESHOLD) continue;

    const last = alertedRepos.get(repoName);
    if (last && now - last < ALERT_COOLDOWN) {
      console.log("⏳ Skipping repeat alert:", repoName);
      continue;
    }

    alertedRepos.set(repoName, now);

    await sendTelegram(
`🚨 SOC INTELLIGENCE CARD

📦 Repo: ${repoName}
🔗 ${buildRepoUrl(repoName)}

📊 Score: ${score.toFixed(2)}
📁 Files: ${repo.files}

🧬 Signal: ${repo.signalScore}
⚙️ Behavior: ${repo.behaviorScore}

Scan: Stable Polling Mode`
    );

    console.log("🚨 ALERT:", repoName);
  }
}

// =========================
// CYCLE
// =========================

async function runCycle() {
  console.log("🔄 Scan cycle started");

  processedFiles.clear();
  global.repoCache = new Map();

  for (const keyword of BASE_KEYWORDS) {
    await processKeyword(keyword);
    await sleep(BASE_SLEEP);
  }

  await evaluateRepos();

  console.log("✅ Cycle complete");
}

// =========================
// WORKER
// =========================

async function startWorker() {
  console.log("🚀 SOC Polling Scanner started");

  while (true) {
    try {
      await runCycle();
      await sleep(10 * 60 * 1000);
    } catch (e) {
      console.error("Worker crash:", e.message);
      await sleep(5000);
    }
  }
}

startWorker();
