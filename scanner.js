require("dotenv").config();

const axios = require("axios");
const pool = require("./db");
const sendTelegram = require("./telegram");

const KEYWORDS = [
  "botToken",
  "chatId",
  "chat_id",
  "MNEMONIC",
  "SEED_PHRASE",
  "-BEGIN PRIVATE KEY-",
  "https://api.telegram.org/bot",
  "PRIVATE_KEY"
];

const sleep = (ms) =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Secret patterns (real detection layer)
 */
const SECRET_PATTERNS = [
  {
    name: "GitHub Token",
    regex: /ghp_[A-Za-z0-9]{36}/g
  },
  {
    name: "GitHub Fine-grained Token",
    regex: /github_pat_[A-Za-z0-9_]{20,}/g
  },
  {
    name: "AWS Access Key",
    regex: /AKIA[0-9A-Z]{16}/g
  },
  {
    name: "Google API Key",
    regex: /AIza[0-9A-Za-z\-_]{35}/g
  },
  {
    name: "Generic API Secret",
    regex: /(api[_-]?key|secret|token|password)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{8,}['"]?/gi
  }
];

/**
 * Detect secrets in file content
 */
function detectSecrets(content) {

  const findings = [];

  for (const pattern of SECRET_PATTERNS) {

    const matches = content.match(pattern.regex);

    if (matches) {
      findings.push({
        type: pattern.name,
        matches: [...new Set(matches)]
      });
    }

  }

  return findings;
}

/**
 * Search GitHub code by keyword
 */
async function searchKeyword(keyword) {

  try {

    const url =
      `https://api.github.com/search/code?q="${keyword}"`;

    const res = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        "Accept": "application/vnd.github+json",
        "User-Agent": "github-monitor"
      }
    });

    return res.data.items || [];

  } catch (err) {
    console.error(`Search error (${keyword}):`, err.message);
    return [];
  }
}

/**
 * Fetch actual file content from GitHub
 */
async function fetchFileContent(item) {

  try {

    const url = item.html_url.replace(
      "github.com",
      "raw.githubusercontent.com"
    ).replace("/blob/", "/");

    const res = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`
      }
    });

    return res.data;

  } catch (err) {

    console.error("File fetch error:", err.message);
    return null;

  }
}

/**
 * Process each search result
 */
async function processKeyword(keyword) {

  const results = await searchKeyword(keyword);

  for (const item of results) {

    try {

      const exists = await pool.query(
        "SELECT id FROM findings WHERE html_url=$1",
        [item.html_url]
      );

      if (exists.rows.length) continue;

      // Save basic match first
      await pool.query(
        `
        INSERT INTO findings
        (keyword, repo_name, file_path, html_url)
        VALUES ($1,$2,$3,$4)
        `,
        [
          keyword,
          item.repository.full_name,
          item.path,
          item.html_url
        ]
      );

      // Fetch file content
      const content = await fetchFileContent(item);

      if (!content) continue;

      // Detect secrets
      const secrets = detectSecrets(content);

      // If secrets found → alert immediately
      if (secrets.length > 0) {

        await sendTelegram(
`🚨 SECRET DETECTED

Keyword: ${keyword}

Repo: ${item.repository.full_name}
File: ${item.path}

Findings:
${JSON.stringify(secrets, null, 2)}

${item.html_url}`
        );

        console.log("🚨 Secret found:", item.html_url);

      } else {

        console.log("✔ Clean match:", item.html_url);

      }

    } catch (err) {
      console.error("Process error:", err.message);
    }

  }
}

/**
 * One full scan cycle
 */
async function runCycle() {

  console.log("🔄 New scan cycle starting...");

  for (const keyword of KEYWORDS) {

    console.log(`🔎 Scanning: ${keyword}`);

    await processKeyword(keyword);

    // small delay between keywords
    await sleep(2000);
  }

  console.log("✅ Cycle complete");
}

/**
 * Infinite worker loop (Railway friendly)
 */
async function startWorker() {

  console.log("🚀 GitHub Secret Monitor Started");

  while (true) {

    try {

      await runCycle();

      console.log("💤 Sleeping 10 minutes...");
      await sleep(10 * 60 * 1000);

    } catch (err) {

      console.error("Worker error:", err.message);

      await sleep(5000);
    }

  }
}

startWorker();
