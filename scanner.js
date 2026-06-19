require("dotenv").config();

const axios = require("axios");
const pool = require("./db");
const sendTelegram = require("./telegram");

const KEYWORDS = [
  "yourdomain.com",
  "projectphoenix"
];

// GitHub rate-safe delay between requests
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

async function searchKeyword(keyword) {

  try {

    const url =
      `https://api.github.com/search/code?q="${keyword}"`;

    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        "Accept": "application/vnd.github+json",
        "User-Agent": "github-monitor-bot"
      }
    });

    return response.data.items || [];

  } catch (err) {

    console.error(`Search error for ${keyword}:`, err.message);
    return [];

  }
}

async function processKeyword(keyword) {

  const results = await searchKeyword(keyword);

  for (const item of results) {

    try {

      const exists = await pool.query(
        "SELECT id FROM findings WHERE html_url=$1",
        [item.html_url]
      );

      if (exists.rows.length) continue;

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

      await sendTelegram(
`🚨 New GitHub Match

Keyword: ${keyword}

Repo: ${item.repository.full_name}
File: ${item.path}

${item.html_url}`
      );

      console.log(`Saved: ${item.html_url}`);

    } catch (err) {
      console.error("Process error:", err.message);
    }
  }
}

async function runCycle() {

  console.log("🔄 Starting scan cycle...");

  for (const keyword of KEYWORDS) {

    console.log(`🔎 Scanning: ${keyword}`);

    await processKeyword(keyword);

    // Small delay between keywords (prevents GitHub rate spikes)
    await sleep(2000);
  }

  console.log("✅ Cycle complete");
}

async function startWorker() {

  console.log("🚀 GitHub Monitor Worker Started");

  while (true) {

    try {

      await runCycle();

      // Wait before next full scan cycle
      console.log("💤 Sleeping for 10 minutes...");
      await sleep(10 * 60 * 1000);

    } catch (err) {

      console.error("Worker crash handled:", err.message);

      // avoid hard crash loop
      await sleep(5000);
    }
  }
}

startWorker();
