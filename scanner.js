require("dotenv").config();

const axios = require("axios");
const pool = require("./db");
const sendTelegram = require("./telegram");

// =========================
// CONFIG
// =========================

const ALERT_THRESHOLD = 15;
const MAX_FILE_SIZE = 800000;
const BASE_SLEEP = 5000;

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
// KEYWORDS
// =========================

const KEYWORDS = [
  "seed phrase",
  "recovery phrase",
  "wallet import",
  "connect wallet",
  "private key",
  "mnemonic",
  "cpanel",
  "wallet sync",
  "rdp",
  "recover assets",
  "wallet authentication",
  "wallet sync",
  "asset recovery",
  "wallet validation",
];

// =========================
// PATTERNS
// =========================

const SECRET_PATTERNS = [
  {
    name: "Seed Phrase Prompt",
    regex: /(seed phrase|recovery phrase|mnemonic phrase)/gi,
    severity: "high",
  },
  {
    name: "Enter Seed Phrase",
    regex: /(enter|input|paste|submit).{0,40}(seed|recovery|mnemonic)/gi,
    severity: "critical",
  },
  {
    name: "Private Key",
    regex: /(private key|walletPrivateKey|secretKey)/gi,
    severity: "critical",
  },
  {
    name: "12/24 Word Phrase",
    regex: /(12[- ]word|24[- ]word).{0,20}(phrase|seed)/gi,
    severity: "critical",
  },
  {
    name: "Telegram Exfiltration",
    regex: /api\.telegram\.org\/bot/i,
    severity: "critical",
  },
/*  {
    name: "Discord Webhook",
    regex: /discord(app)?\.com\/api\/webhooks/i,
    severity: "critical",
  },
  {
    name: "AWS Key",
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: "critical",
  },
  {
    name: "Google API Key",
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: "critical",
  },
  {
    name: "Paystack Secret",
    regex: /sk_(live|test)_[A-Za-z0-9]{20,}/gi,
    severity: "critical",
  },
  {
    name: "Flutterwave Key",
    regex: /FLW(SECK|SECK_TEST)-[A-Za-z0-9_-]+/gi,
    severity: "critical",
  }, 
  {
    name: "Database URL",
    regex: /(mongodb|postgres|mysql):\/\/[^\s"']+/gi,
    severity: "critical",
  }, */
];

// =========================
// 🚫 NOISE FILTER (NEW FIX)
// =========================

function shouldSkipFile(item) {
  const path = (item.path || "").toLowerCase();

  // markdown / docs noise
  if (
    path.endsWith(".md") ||
    path.endsWith(".markdown") ||
    path.includes("readme") ||
    path.includes("license") ||
    path.includes("changelog")
  ) return true;

  // documentation folders
  if (
    path.includes("/docs/") ||
    path.includes("/doc/") ||
    path.includes("/documentation/")
  ) return true;

  // samples / examples
  if (
    path.includes("/example/") ||
    path.includes("/examples/") ||
    path.includes("/sample/") ||
    path.includes("/samples/")
  ) return true;

  // common non-source junk
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
    const url = `https://api.github.com/search/code?q=${encodeURIComponent(
      keyword
    )}+in:file`;

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
// DB INSERT (SAFE)
// =========================

async function safeInsert(item, keyword, score, severity) {
  try {
    await pool.query(
      `
      INSERT INTO findings
      (keyword, repo_name, file_path, html_url, score, severity)
      VALUES ($1,$2,$3,$4,$5,$6)
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
      // 🚫 HARD SKIP NOISE FILES EARLY
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
// CYCLE
// =========================

async function runCycle() {
  console.log("🔄 Scan cycle starting...");

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
