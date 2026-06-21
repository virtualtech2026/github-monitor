require("dotenv").config();

const axios = require("axios");
const pool = require("./db");
const sendTelegram = require("./telegram");

// =========================
// CONFIG
// =========================

const ALERT_THRESHOLD = 20;
const MAX_FILE_SIZE = 800000;
const BASE_SLEEP = 5000;

// =========================
// DEDUP CACHE (FIX #1)
// =========================

const processedUrls = new Set();

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
// KEYWORDS (FIX #5)
// =========================

const KEYWORDS = [
  ...new Set([
    "wallet drainer",
    "crypto drainer",
    "wallet connect phishing",
    "wallet connect scam",
    "seed phrase",
    "recovery phrase",
    "mnemonic phrase",
    "import wallet",
    "restore wallet",
    "connect wallet",
    "wallet verification",
    "wallet validation",
    "wallet synchronization",
    "wallet migration",
    "claim airdrop",
    "claim rewards",
    "claim token",
    "claim nft",
    "free mint",
    "wallet checker",
    "wallet recovery",
    "wallet unlock",
    "wallet authenticate",
    "wallet session expired",
    "walletconnect",
    "walletconnect v2",
    "web3 modal",
    "rainbowkit",
    "wagmi",
    "ethers.js",
    "drain wallet",
    "sweep wallet",
    "sweeper bot",
    "auto transfer",
    "auto withdraw",
    "transfer all balance",
    "send max balance",
    "setapprovalforall",
    "permit2",
    "signTypedData",
    "eth_signTypedData",
    "personal_sign"
  ])
];

// =========================
// PATTERNS
// =========================

const SECRET_PATTERNS = [
  {
    name: "Seed Phrase Collection",
    regex: /(seed phrase|recovery phrase|mnemonic phrase)/gi,
    severity: "high",
  },
  {
    name: "Wallet Recovery Prompt",
    regex: /(import|restore|recover).{0,50}(wallet)/gi,
    severity: "high",
  },
  {
    name: "Seed Phrase Submission",
    regex: /(enter|input|paste|submit).{0,50}(seed|mnemonic|recovery)/gi,
    severity: "critical",
  },
  {
    name: "12/24 Word Phrase",
    regex: /(12|24)[ -]?word.{0,30}(phrase|seed)/gi,
    severity: "critical",
  },
  {
    name: "Telegram Exfiltration",
    regex: /api\.telegram\.org\/bot/i,
    severity: "critical",
  },
  {
    name: "Discord Webhook",
    regex: /discord(app)?\.com\/api\/webhooks/i,
    severity: "critical",
  },
  {
    name: "Webhook Exfiltration",
    regex: /https?:\/\/.*webhook/i,
    severity: "critical",
  },
  {
    name: "Wallet Approval Abuse",
    regex: /setApprovalForAll/gi,
    severity: "high",
  },
  {
    name: "Unlimited Allowance",
    regex: /increaseAllowance/gi,
    severity: "high",
  },
  {
    name: "Permit Signature Abuse",
    regex: /permit2?/gi,
    severity: "high",
  },
  {
    name: "Typed Data Signature",
    regex: /eth_signTypedData/gi,
    severity: "medium",
  },
  {
    name: "Personal Sign Request",
    regex: /personal_sign/gi,
    severity: "medium",
  },
  {
    name: "WalletConnect Usage",
    regex: /walletconnect/gi,
    severity: "medium",
  },
  {
    name: "Transfer Entire Balance",
    regex: /(transfer all balance|send max balance|drain wallet|sweep wallet)/gi,
    severity: "critical",
  },
  {
    name: "Targeted Wallet Brands",
    regex: /(metamask|trust wallet|coinbase wallet|phantom|rainbow|safepal|exodus|ledger|trezor)/gi,
    severity: "medium",
  }
];

// =========================
// 🚫 NOISE FILTER
// =========================

function shouldSkipFile(item) {
  const path = (item.path || "").toLowerCase();

  if (
    path.endsWith(".md") ||
    path.endsWith(".markdown") ||
    path.includes("readme") ||
    path.includes("license") ||
    path.includes("changelog")
  ) return true;

  if (
    path.includes("/docs/") ||
    path.includes("/doc/") ||
    path.includes("/documentation/")
  ) return true;

  if (
    path.includes("/example/") ||
    path.includes("/examples/") ||
    path.includes("/sample/") ||
    path.includes("/samples/")
  ) return true;

  if (
    path.includes(".min.js") ||
    path.includes(".map") ||
    path.includes("package-lock.json")
  ) return true;

  return false;
}

// =========================
// DETECTION ENGINE
// =========================

function detectSecrets(content) {
  const findings = [];
  let score = 0;

  for (const p of SECRET_PATTERNS) {
    const matches = content.match(p.regex);

    if (matches) {
      const unique = [...new Set(matches)];
      const weight = WEIGHTS[p.severity] || 0;

      score += weight;

      findings.push({
        type: p.name,
        severity: p.severity,
        matches: unique,
        weight,
      });
    }
  }

  return { findings, score };
}

// =========================
// GITHUB SEARCH
// =========================

async function searchKeyword(keyword) {
  try {
    const url = `https://api.github.com/search/code?q=${encodeURIComponent(keyword)}+in:file`;

    const res = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "org-secret-scanner",
      },
      validateStatus: () => true,
    });

    if (res.status === 403) {
      console.error("⚠️ Rate limit hit. Sleeping 60s...");
      await new Promise((r) => setTimeout(r, 60000));
      return [];
    }

    return res.data?.items || [];
  } catch (err) {
    console.error(`Search error (${keyword}):`, err.message);
    return [];
  }
}

// =========================
// FETCH FILE
// =========================

async function fetchFileContent(item) {
  try {
    const url = item.html_url
      .replace("github.com", "raw.githubusercontent.com")
      .replace("/blob/", "/");

    const res = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      },
      maxContentLength: MAX_FILE_SIZE,
    });

    if (!res.data || res.data.length > MAX_FILE_SIZE) return null;

    return res.data;
  } catch {
    return null;
  }
}

// =========================
// SAFE INSERT (FIX #4)
// =========================

async function safeInsert(item, keyword, score, severity) {
  try {
    await pool.query(
      `
      INSERT INTO findings
      (keyword, repo_name, file_path, html_url, score, severity)
      VALUES ($1,$2,$3,$4,$5,$6)
      ON CONFLICT (html_url) DO NOTHING
      `,
      [
        keyword,
        item.repository.full_name,
        item.path,
        item.html_url,
        score,
        severity,
      ]
    );
  } catch (err) {
    console.error("DB insert warning:", err.message);
  }
}

// =========================
// PROCESS KEYWORD
// =========================

async function processKeyword(keyword) {
  const results = await searchKeyword(keyword);

  for (const item of results) {
    try {
      // 🚫 FIX #1: in-memory dedupe
      if (processedUrls.has(item.html_url)) continue;

      // 🚫 HARD SKIP NOISE FILES
      if (shouldSkipFile(item)) {
        console.log("🚫 Skipped noisy file:", item.path);
        continue;
      }

      const exists = await pool.query(
        "SELECT id FROM findings WHERE html_url=$1",
        [item.html_url]
      );

      if (exists.rows.length) continue;

      const content = await fetchFileContent(item);
      if (!content) continue;

      const { findings, score } = detectSecrets(content);

      const severity =
        score >= 15 ? "HIGH" : score >= 7 ? "MEDIUM" : "LOW";

      // mark processed EARLY (prevents duplicates across keywords)
      processedUrls.add(item.html_url);

      await safeInsert(item, keyword, score, severity);

      if (score >= ALERT_THRESHOLD) {
        await sendTelegram(
          `🚨 SECURITY ALERT

Score: ${score}
Severity: ${severity}
Keyword: ${keyword}

Repo: ${item.repository.full_name}
File: ${item.path}

Findings:
${JSON.stringify(findings, null, 2)}

${item.html_url}`
        );

        // FIX #6: mark alerted
        await pool.query(
          "UPDATE findings SET alerted=TRUE WHERE html_url=$1",
          [item.html_url]
        );

        console.log("🚨 ALERT:", item.html_url);
      } else {
        console.log("✔ OK:", item.html_url);
      }
    } catch (err) {
      console.error("Process error:", err.message);
    }
  }
}

// =========================
// CYCLE (FIX #2)
// =========================

async function runCycle() {
  console.log("🔄 Scan cycle starting...");

  processedUrls.clear();

  for (const keyword of KEYWORDS) {
    console.log("🔎", keyword);

    await processKeyword(keyword);

    await new Promise((r) => setTimeout(r, BASE_SLEEP));
  }

  console.log("✅ Cycle complete");
}

// =========================
// WORKER LOOP
// =========================

async function startWorker() {
  console.log("🚀 Scanner started");

  while (true) {
    try {
      await runCycle();

      console.log("💤 Sleeping 10 minutes...");
      await new Promise((r) => setTimeout(r, 10 * 60 * 1000));
    } catch (err) {
      console.error("Worker crash:", err.message);
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
}

startWorker();
