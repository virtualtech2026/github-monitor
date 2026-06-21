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

const processedFiles = new Set();     // per cycle file dedupe
const seenReposCycle = new Set();     // per cycle repo dedupe
const alertedRepos = new Map();       // cooldown tracker

// =========================
// BACKOFF STATE (FIX 403)
// =========================

let githubBackoff = 1000;

// =========================
// WEIGHTS
// =========================

const WEIGHTS = {
  low: 1,
  medium: 3,
  high: 7,
  critical: 15,
};

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
// KEYWORD EXPANSION (🔥 FIX #1)
// =========================

function expandKeyword(keyword) {
  const suffixes = [
    "",
    " js",
    " ethers",
    " walletconnect",
    " web3",
    " phishing",
    " drain",
  ];

  return suffixes.map(s => keyword + s);
}

// =========================
// BASE KEYWORDS
// =========================

const BASE_KEYWORDS = [
  "wallet drainer",
  "crypto drainer",
  "seed phrase",
  "recovery phrase",
  "mnemonic phrase",
  "wallet connect phishing",
  "setapprovalforall",
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
// LEGIT FILTER
// =========================

const LEGIT_CONTEXT = [
  /next\.js|react|vite|nuxt/i,
  /hardhat|foundry|ethers\.js|wagmi/i,
  /openzeppelin|uniswap|aave/i,
  /tutorial|example|template|docs/i
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
    if (p.regex.test(content)) signalScore += WEIGHTS[p.severity] || 0;
  }

  for (const b of BEHAVIOR_PATTERNS) {
    if (b.regex.test(content)) behaviorScore += b.weight;
  }

  for (const l of LEGIT_CONTEXT) {
    if (l.test(content)) legitPenalty += 8;
  }

  return { signalScore, behaviorScore, legitPenalty };
}

// =========================
// REPO AGGREGATOR
// =========================

function updateRepo(repoName, data) {
  if (!seenReposCycle.has(repoName)) {
    seenReposCycle.add(repoName);
  }

  if (!global.repoCache) global.repoCache = new Map();

  const repoCache = global.repoCache;

  if (!repoCache.has(repoName)) {
    repoCache.set(repoName, {
      signalScore: 0,
      behaviorScore: 0,
      legitPenalty: 0,
      files: 0
    });
  }

  const repo = repoCache.get(repoName);

  repo.signalScore += data.signalScore;
  repo.behaviorScore += data.behaviorScore;
  repo.legitPenalty += data.legitPenalty;
  repo.files += 1;
}

// =========================
// SCORE MODEL
// =========================

function computeRepoScore(repo) {
  let score =
    repo.signalScore +
    repo.behaviorScore * 1.5 -
    repo.legitPenalty;

  if (repo.behaviorScore > 20 && repo.signalScore > 10) {
    score += 10;
  }

  return score;
}

// =========================
// GITHUB SEARCH (FIX 403 + BACKOFF)
// =========================

async function searchKeyword(keyword) {
  const results = [];

  for (let page = 1; page <= 3; page++) {
    const url =
      `https://api.github.com/search/code?q=${encodeURIComponent(keyword)}+in:file` +
      `&per_page=30&page=${page}&sort=indexed`;

    try {
      const res = await axios.get(url, {
        headers: {
          Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
          "User-Agent": "soc-scanner"
        }
      });

      githubBackoff = 1000; // reset on success

      const items = res.data?.items || [];
      if (!items.length) break;

      results.push(...items);

      await sleep(800);

    } catch (err) {
      const status = err.response?.status;

      if (status === 403) {
        console.log("⚠️ 403 rate limit hit. backing off...");

        await sleep(githubBackoff);
        githubBackoff = Math.min(githubBackoff * 2, 60000);

        break;
      }

      console.error("Search error:", err.message);
      break;
    }
  }

  return results;
}

// =========================
// FETCH FILE
// =========================

async function fetchFile(item) {
  try {
    const url = item.html_url
      .replace("github.com", "raw.githubusercontent.com")
      .replace("/blob/", "/");

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
  const expanded = expandKeyword(keyword);

  for (const q of expanded) {
    const results = await searchKeyword(q);

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
}

// =========================
// SOC ALERT ENGINE
// =========================

async function evaluateRepos() {
  const repoCache = global.repoCache || new Map();
  const now = Date.now();

  for (const [repoName, repo] of repoCache.entries()) {

    const score = computeRepoScore(repo);

    const repoUrl = buildRepoUrl(repoName);

    const last = alertedRepos.get(repoName);
    if (last && now - last < ALERT_COOLDOWN) {
      console.log("⏳ Skipping repeat alert:", repoName);
      continue;
    }

    if (score < ALERT_THRESHOLD) continue;

    alertedRepos.set(repoName, now);

    await sendTelegram(
`🚨 SOC POLLING INTELLIGENCE CARD

━━━━━━━━━━━━━━━━━━
${score >= HIGH_CONFIDENCE_THRESHOLD ? "🔴 CONFIRMED DRAINER" : "🟠 HIGH RISK"}
━━━━━━━━━━━━━━━━━━

📦 Repo: ${repoName}
🔗 ${repoUrl}

📊 Score: ${score.toFixed(2)}
📁 Files: ${repo.files}

🧬 Signal: ${repo.signalScore}
⚙️ Behavior: ${repo.behaviorScore}
⚠️ Penalty: ${repo.legitPenalty}

━━━━━━━━━━━━━━━━━━
Scan: GitHub Polled + Expanded Queries
━━━━━━━━━━━━━━━━━━`
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
      console.log("💤 sleeping...");
      await sleep(10 * 60 * 1000);
    } catch (e) {
      console.error("Worker crash:", e.message);
      await sleep(5000);
    }
  }
}

startWorker();r
