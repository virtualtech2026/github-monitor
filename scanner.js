require("dotenv").config();

const axios = require("axios");
const pool = require("./db");
const sendTelegram = require("./telegram");

const KEYWORDS = [
  "yourdomain.com",
  "projectphoenix"
];

async function searchKeyword(keyword) {

  const url =
    `https://api.github.com/search/code?q="${keyword}"`;

  const response = await axios.get(url, {
    headers: {
      Authorization:
        `Bearer ${process.env.GITHUB_TOKEN}`
    }
  });

  return response.data.items || [];
}

async function processKeyword(keyword) {

  const results =
    await searchKeyword(keyword);

  for (const item of results) {

    const exists =
      await pool.query(
        "SELECT id FROM findings WHERE html_url=$1",
        [item.html_url]
      );

    if (exists.rows.length)
      continue;

    await pool.query(
      `
      INSERT INTO findings
      (
        keyword,
        repo_name,
        file_path,
        html_url
      )
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
`New GitHub Match

Keyword: ${keyword}

Repository:
${item.repository.full_name}

File:
${item.path}

${item.html_url}`
    );

  }

}

async function run() {

  for (const keyword of KEYWORDS) {

    try {

      console.log(
        `Scanning ${keyword}`
      );

      await processKeyword(
        keyword
      );

    } catch(err) {

      console.error(
        keyword,
        err.message
      );

    }

  }

  process.exit();

}

run();
