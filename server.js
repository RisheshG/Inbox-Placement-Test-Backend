const express = require("express");
const { v4: uuidv4 } = require("uuid");
const imaps = require("imap-simple");
const mysql = require("mysql2");
const moment = require("moment");
const axios = require("axios");
const qs = require("querystring");
const cheerio = require("cheerio"); // To parse Outlook HTML emails

const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Rishesh@123",
  database: "inboxPlacement",
});

db.query(`
  CREATE TABLE IF NOT EXISTS TestResults (
    id INT AUTO_INCREMENT PRIMARY KEY,
    testCode VARCHAR(255),
    email VARCHAR(255),
    status VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

const testAccounts = [
  { email: "tmm003937@gmail.com", password: "fekg mego jqlw pizn" },
  { email: "mta872679@gmail.com", password: "dppb jbar acqq orqz" },
];

const outlookAccount = {
  email: "brijesh@xleadoutreach.com",
  client_id: "29c8707e-876a-4833-8c31-4cad33a8ac0b",
  tenant_id: "751d98b4-f8be-4510-9ccc-97bdb4e50d02",
  client_secret: "wn28Q~0N-DlfWfyiSQfY.GqFLAfN4g1EuuNkhcHy",
};

app.post("/generate-test-code", (req, res) => {
  const testCode = uuidv4();
  res.json({ testCode });
});

const checkMailboxes = async (testCode) => {
  console.log(`📩 Starting mailbox check for test code: ${testCode}`);
  const fiveMinutesAgo = moment().subtract(5, "minutes");

  for (const account of testAccounts) {
    const config = {
      imap: {
        user: account.email,
        password: account.password,
        host: "imap.gmail.com",
        port: 993,
        tls: true,
        tlsOptions: { rejectUnauthorized: false },
        authTimeout: 3000,
      },
    };

    try {
      console.log(`🔗 Connecting to ${account.email}...`);
      const connection = await imaps.connect(config);
      console.log(`✅ Connected to ${account.email}`);

      const searchEmails = async (folderName) => {
        await connection.openBox(folderName);
        const searchCriteria = [["SINCE", fiveMinutesAgo.format("DD-MMM-YYYY")]];
        const fetchOptions = { bodies: ["HEADER", "TEXT"], markSeen: false };
        const messages = await connection.search(searchCriteria, fetchOptions);

        return messages.some((msg) => {
          const body = msg.parts.find((part) => part.which === "TEXT")?.body || "";
          return body.toLowerCase().includes(testCode.toLowerCase());
        });
      };

      const foundInInbox = await searchEmails("INBOX");
      if (foundInInbox) {
        console.log(`📨 Test email found in INBOX for ${account.email}`);
        db.query("INSERT INTO TestResults (testCode, email, status) VALUES (?, ?, ?)", [
          testCode,
          account.email,
          "Inbox",
        ]);
        await connection.end();
        continue;
      }

      const foundInSpam = await searchEmails("[Gmail]/Spam");
      db.query("INSERT INTO TestResults (testCode, email, status) VALUES (?, ?, ?)", [
        testCode,
        account.email,
        foundInSpam ? "Spam" : "Not Found",
      ]);
      console.log(
        `📨 Email for ${account.email} found in ${foundInSpam ? "SPAM" : "NOT FOUND"}`
      );
      await connection.end();
    } catch (error) {
      console.error(`❌ Error with ${account.email}:`, error.message);
      db.query("INSERT INTO TestResults (testCode, email, status) VALUES (?, ?, ?)", [
        testCode,
        account.email,
        "Error",
      ]);
    }
  }

  try {
    console.log(`📡 Fetching emails for Outlook account: ${outlookAccount.email}`);

    // Get Outlook access token
    const tokenResponse = await axios.post(
      `https://login.microsoftonline.com/${outlookAccount.tenant_id}/oauth2/v2.0/token`,
      qs.stringify({
        client_id: outlookAccount.client_id,
        client_secret: outlookAccount.client_secret,
        scope: "https://graph.microsoft.com/.default",
        grant_type: "client_credentials",
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const accessToken = tokenResponse.data.access_token;

    // Fetch latest 10 messages from Outlook inbox
    const messagesResponse = await axios.get(
      `https://graph.microsoft.com/v1.0/users/${outlookAccount.email}/mailFolders/inbox/messages?$top=10`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const messages = messagesResponse.data.value;

    // Check if testCode is inside any email content
    const foundInOutlookInbox = messages.some((msg) => {
      const bodyContent = msg.body?.content || "";

      // Convert HTML to text using Cheerio
      const $ = cheerio.load(bodyContent);
      const plainText = $("body").text().toLowerCase(); // Extract plain text content

      return plainText.includes(testCode.toLowerCase());
    });

    db.query("INSERT INTO TestResults (testCode, email, status) VALUES (?, ?, ?)", [
      testCode,
      outlookAccount.email,
      foundInOutlookInbox ? "Inbox" : "Not Found",
    ]);

    console.log(
      `📩 Test email ${foundInOutlookInbox ? "FOUND" : "NOT FOUND"} in Outlook Inbox`
    );
  } catch (error) {
    console.error(`❌ Error fetching Outlook emails:`, error.message);
    db.query("INSERT INTO TestResults (testCode, email, status) VALUES (?, ?, ?)", [
      testCode,
      outlookAccount.email,
      "Error",
    ]);
  }
};

app.post("/check-mails", async (req, res) => {
  const { testCode } = req.body;
  await checkMailboxes(testCode);
  res.json({ message: `📬 Mailbox check initiated for ${testCode}` });
});

app.get("/results/:testCode", (req, res) => {
  db.query(
    "SELECT email, status FROM TestResults WHERE testCode = ?",
    [req.params.testCode],
    (err, results) => {
      if (err) return res.status(500).json({ message: "Database error.", error: err });
      if (results.length === 0)
        return res.status(404).json({ message: "Test code not found." });
      res.json({ testCode: req.params.testCode, results });
    }
  );
});

app.listen(3000, () => console.log("🚀 Server running on port 3000"));
