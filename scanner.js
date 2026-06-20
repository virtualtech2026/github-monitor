require("dotenv").config();

const axios = require("axios");
const pool = require("./db");
const sendTelegram = require("./telegram");

// =========================
// CONFIG
// =========================

const ALERT_THRESHOLD = 15;
const MAX_FILE_SIZE = 800000; // 800KB safety limit

const WEIGHTS = {
  low: 1,
  medium: 3,
  high: 7,
  critical: 15,
};

// =========================
// KEYWORDS (kept but cleaned slightly)
// =========================

const KEYWORDS = [
  "seed phrase",
  "recovery phrase",
  "wallet import",
  "connect wallet",
  "private key",
  "mnemonic",
  "cpanel",
  "webmail",
  "rdp",
  "smtp",
  "database password",
  "api key",
  "secret key",
  "stripe",
  "paystack",
  "flutterwave",
];

// =========================
// SECRET PATTERNS (CLEANED + DE-DUPED)
// =========================

const SECRET_PATTERNS = [
  // ================= Crypto =================
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
    name: "Import Wallet",
    regex: /(import wallet|restore wallet|recover wallet)/gi,
    severity: "high",
  },
  {
    name: "Private Key Exposure",
    regex: /(private key|walletPrivateKey|secretKey)/gi,
    severity: "critical",
  },
  {
    name: "12/24 Word Phrase",
    regex: /(12[- ]word|24[- ]word).{0,20}(phrase|seed)/gi,
    severity: "critical",
  },

  // ================= Exfiltration =================
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

  // ================= Cloud / Dev =================
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
    name: "JWT Secret",
    regex: /JWT_SECRET|jwtSecret/i,
    severity: "high",
  },

  // ================= Payment (important fix: more realistic) =================
  {
    name: "Paystack Secret Key",
    regex: /sk_(live|test)_[A-Za-z0-9]{20,}/gi,
    severity: "critical",
  },
  {
    name: "Flutterwave Key",
    regex: /FLW(SECK|SECK_TEST)-[A-Za-z0-9_-]+/gi,
    severity: "critical",
  },

  // ================= Servers =================
  {
    name: "SSH Private Key",
    regex: /-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----/g,
    severity: "critical",
  },

  // ================= Databases =================
  {
    name: "Database URL",
    regex: /(mongodb|postgres|mysql|redis):\/\/[^\s"']+/gi,
    severity: "critical",
  },

  // ================= Generic (VERY limited now) =================
  {
    name: "Generic Env Secret",
    regex: /(API_KEY|SECRET|PASSWORD|TOKEN)\s*=\s*["']?[A-Za-z0-9_\-]{10,}["']?/gi,
    severity: "medium",
  },
];

// =========================
// DETECTION ENGINE
// =========================

function detectSecrets(content) {
  const findings = [];
  let score = 0;

  for (const pattern of SECRET_PATTERNS) {
    const matches = content.match(pattern.regex);

    if (matches) {
      const unique = [...new Set(matches)];

      const weight = WEIGHTS[pattern.severity] || 0;
      score += weight;

      findings.push({
        type: pattern.name,
        severity: pattern.severity,
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
    });

    return res.data.items || [];
  } catch (err) {
    console.error(`Search error (${keyword}):`, err.message);
    return [];
  }
}

// =========================
// FETCH FILE (SAFE)
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

    if (res.data?.length > MAX_FILE_SIZE) return null;

    return res.data;
  } catch (err) {
    return null;
  }
}

// =========================
// PROCESS RESULT
// =========================

async function processKeyword(keyword) {
  const results = await searchKeyword(keyword);

  for (const item of results) {
    try {
      const exists = await pool.query(
        "SELECT id FROM findings WHERE html_url=$1",
        [item.html_url]
      );

      if (exists.rows.length) continue;

      const content = await fetchFileContent(item);
      if (!content) continue;

      const { findings, score } = detectSecrets(content);

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
          score >= 15 ? "HIGH" : "LOW",
        ]
      );

      if (score >= ALERT_THRESHOLD) {
        await sendTelegram(
          `🚨 SECRET RISK DETECTED

Score: ${score}
Keyword: ${keyword}

Repo: ${item.repository.full_name}
File: ${item.path}

Findings:
${JSON.stringify(findings, null, 2)}

${item.html_url}`
        );

        console.log("🚨 ALERT:", item.html_url);
      } else {
        console.log("✔ Low risk:", item.html_url);
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
    console.log(`🔎 ${keyword}`);
    await processKeyword(keyword);
    await new Promise((r) => setTimeout(r, 1500));
  }

  console.log("✅ Cycle complete");
}

// =========================
// WORKER
// =========================

async function startWorker() {
  console.log("🚀 Scanner started");

  while (true) {
    try {
      await runCycle();
      console.log("💤 Sleeping...");
      await new Promise((r) => setTimeout(r, 10 * 60 * 1000));
    } catch (err) {
      console.error("Worker error:", err.message);
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
}

startWorker();
