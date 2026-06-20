require("dotenv").config();

const axios = require("axios");
const pool = require("./db");
const sendTelegram = require("./telegram");

const KEYWORDS = [
    "enter your seed phrase",
  "enter recovery phrase",
  "wallet synchronization",
  "connect wallet manually",
  "restore wallet",
  "import wallet",
  "verify wallet",
  "confirm wallet ownership",
  "paste private key",
  "wallet validation",
  "12 word phrase",
  "24 word phrase",
  "recover assets",
  "recover wallet",
  "unlock wallet",
  "botToken",
  "chatId",
  "chat_id",
  "MNEMONIC",
  "SEED_PHRASE",
  "-BEGIN PRIVATE KEY-",
  "remote desktop",
  "rdp",
  "cpanel",
  "whm",
  "webmail",
  "roundcube",
  "horde",
  "smtp",
  "mail_password",
  "email_password",
  "smtp_password",
  "CPANEL_PASSWORD=",
  "https://api.telegram.org/bot",
  "database.sql",
  "backup.sql",
  "wallet.dat",
  "id_ed25519",
  "id_rsa",
  "service-account.json",
  "credentials.json",
  "config.json",
  "config.js",
  ".env.local",
  ".env.production",
  ".env",
  "PRIVATE_KEY"
];

const sleep = (ms) =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Secret patterns (real detection layer)
 */
const SECRET_PATTERNS = [
  // =========================
// Crypto / Wallet Drainer Detection
// =========================

{
  name: "Seed Phrase Keywords",
  regex: /(seed phrase|recovery phrase|secret phrase|mnemonic phrase)/gi
},

{
  name: "Enter Seed Phrase",
  regex: /(enter|input|paste|submit).{0,40}(seed|recovery|mnemonic|secret).{0,20}phrase/gi
},

{
  name: "Import Wallet",
  regex: /(import wallet|restore wallet|recover wallet|wallet restore)/gi
},

{
  name: "Connect Wallet Manually",
  regex: /(connect wallet manually|manual wallet connection|manual connect)/gi
},

{
  name: "Paste Private Key",
  regex: /(paste|enter|input).{0,20}(private key)/gi
},

{
  name: "Private Key Variable",
  regex: /(privateKey|walletPrivateKey|secretKey)/g
},

{
  name: "Mnemonic Variable",
  regex: /(mnemonic|seedPhrase|recoveryPhrase|walletSeed)/g
},

{
  name: "Wallet Verification Prompt",
  regex: /(wallet verification|required verification|verify wallet ownership)/gi
},

{
  name: "Wallet Synchronization Scam Text",
  regex: /(wallet synchronization|synchronize wallet|sync wallet now)/gi
},

{
  name: "12 Word Phrase Prompt",
  regex: /(12[- ]word phrase|12 word recovery phrase)/gi
},

{
  name: "24 Word Phrase Prompt",
  regex: /(24[- ]word phrase|24 word recovery phrase)/gi
},

{
  name: "Mnemonic Sent via API",
  regex: /(mnemonic|seedPhrase|recoveryPhrase).{0,100}(fetch|axios\.post|XMLHttpRequest)/gis
},

{
  name: "Wallet Import Endpoint",
  regex: /(\/wallet\/import|\/wallet\/restore|\/api\/wallet\/import)/gi
},

{
  name: "Suspicious Wallet Form Field",
  regex: /(textarea|input).{0,100}(mnemonic|seedPhrase|recoveryPhrase|privateKey)/gis
},

{
  name: "Telegram Exfiltration",
  regex: /api\.telegram\.org\/bot/gi
},

{
  name: "Discord Webhook",
  regex: /discord(?:app)?\.com\/api\/webhooks/gi
},

{
  name: "Webhook Exfiltration",
  regex: /(webhook|sendToTelegram|sendToDiscord)/gi
},
  {
  name: "RDP Password Variable",
  regex: /(RDP_PASSWORD|REMOTE_DESKTOP_PASSWORD)\s*[:=]\s*["'][^"']+["']/gi
},
  {
  name: "Windows Admin Credentials",
  regex: /(administrator|admin)\s*[:=]\s*["'][^"']{6,}["']/gi
},
  {
  name: "cPanel Credentials",
  regex: /(CPANEL_PASSWORD|CPANEL_USER|CPANEL_USERNAME)\s*[:=]\s*["'][^"']+["']/gi
},
{
  name: "Webmail Credentials",
  regex: /(WEBMAIL_PASSWORD|EMAIL_PASSWORD|MAIL_PASSWORD)\s*[:=]\s*["'][^"']+["']/gi
},
  {
  name: "SMTP Credentials",
  regex: /(SMTP_USER|SMTP_USERNAME|SMTP_PASS|SMTP_PASSWORD)\s*[:=]\s*["'][^"']+["']/gi
},
  {
  name: "Generic Login Credentials",
  regex: /(username|user|login)\s*[:=]\s*["'][^"']+["'].*?(password|pass)\s*[:=]\s*["'][^"']+["']/gis
},
  // Paystack (example detection)

  {

    name: "Paystack Secret Key",

    regex: /sk_(live|test)_[A-Za-z0-9]{20,}/gi

  },
  // Flutterwave (example detection)

  {

    name: "Flutterwave Secret Key",

    regex: /FLW(SECK|SECK_TEST)-[A-Za-z0-9_-]+/gi

  },

// Telegram

  {

    name: "Telegram Bot Token",

    regex: /\b\d{8,12}:[A-Za-z0-9_-]{35}\b/g

  },

// BIP39 Seed Phrase (heuristic only)

  {

    name: "Possible Seed Phrase",

    regex: /\b(?:abandon|ability|able|about|above|absent|absorb).{20,200}/gi

  },
    // SMTP Password Variables

  {

    name: "SMTP Credentials",

    regex: /(SMTP_PASS|MAIL_PASSWORD|EMAIL_PASSWORD)\s*[:=]\s*["'][^"']+["']/gi

  },

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
