const express = require("express");
const { v4: uuidv4 } = require("uuid");
const imaps = require("imap-simple");
const { Pool } = require("pg"); // Changed from mysql2 to pg
const moment = require("moment");
const axios = require("axios");
const qs = require("querystring");
const cheerio = require("cheerio");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const csv = require("csv-parser");

const espMapping = {
  // Pro Gmail accounts
  'Patricia@emaildeliveryreport.com': 'pro-gmail',
  'l.Patricia@emaildeliveryreport.net': 'pro-gmail',
  'lindaPatricia@xemaildeliveryreport.com': 'pro-gmail',
  'Linda@xemaildeliveryreport.com': 'pro-gmail',
  'linda.patricia@xemaildeliveryreport.com': 'pro-gmail',
  
  // Pro Outlook accounts
  'brijesh@xleadoutreach.com': 'pro-outlook',
  'mahendra@xleadsconsulting.com': 'pro-outlook',
  'lakhendra@xleadsconsulting.com': 'pro-outlook',
  'xgrowthtech@xleadsconsulting.com': 'pro-outlook',
  'audit@xleadoutreach.com': 'pro-outlook',
  
  // Regular Gmail accounts
  'tmm003937@gmail.com': 'gmail',
  'mta872679@gmail.com': 'gmail',
  'houseisitter@gmail.com': 'gmail',
  'malaikaarora983475@gmail.com': 'gmail',
  'rheadutta096@gmail.com': 'gmail'
};

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(cors());

// PostgreSQL connection with your Render credentials
const db = new Pool({
  user: 'inbox_placement_db_user',
  host: 'dpg-cvja253ipnbc73e08f8g-a.oregon-postgres.render.com',
  database: 'inbox_placement_db',
  password: 'S9gnQfIRBkaceUXHD5okchdpObouAP6X',
  port: 5432,
  ssl: {
    rejectUnauthorized: false // Required for Render's PostgreSQL
  }
});

// Test database connection
db.connect()
  .then(() => console.log("✅ Connected to PostgreSQL database"))
  .catch(err => console.error("❌ Database connection failed:", err.message));

// Create necessary tables
const createTables = async () => {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS Users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        credits INTEGER DEFAULT 10,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS TestResults (
        id SERIAL PRIMARY KEY,
        userId INTEGER,
        testCode VARCHAR(255),
        email VARCHAR(255),
        status VARCHAR(255),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        emailContent TEXT,
        emailHeaders TEXT,
        FOREIGN KEY (userId) REFERENCES Users(id)
      )
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS TestRecipients (
        id SERIAL PRIMARY KEY,
        userId INTEGER,
        testCode VARCHAR(255),
        recipients TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES Users(id)
      )
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS EmailAnalysis (
        id SERIAL PRIMARY KEY,
        testResultId INTEGER,
        subject TEXT,
        fromEmail TEXT,
        date TEXT,
        authentication JSON,
        domainBlacklistCheck JSON,
        ipBlacklistCheck JSON,
        linkStatuses JSON,
        spamWordAnalysis JSON,
        emailContent TEXT,
        mxRecords TEXT,
        mxRecordsData JSON,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (testResultId) REFERENCES TestResults(id)
      )
    `);

    console.log("✅ Tables created or already exist");
  } catch (err) {
    console.error("❌ Error creating tables:", err.message);
  }
};

createTables();

const gmailAccounts = [
  { email: "tmm003937@gmail.com", password: "fekg mego jqlw pizn" },
  { email: "mta872679@gmail.com", password: "dppb jbar acqq orqz" },
  { email: "houseisitter@gmail.com", password: "uagt sofj owvc wkcg" },
  { email: "malaikaarora983475@gmail.com", password: "lhkh puyy cyhr fwah" },
  { email: "rheadutta096@gmail.com", password: "lrgw vvpq kwfm edln" },
  { email: "Patricia@emaildeliveryreport.com", password: "lhxp afdy rrbt utsq" },
  { email: "l.Patricia@emaildeliveryreport.net", password: "utwn jrcu wyvq wcdn" },
  { email: "lindaPatricia@xemaildeliveryreport.com", password: "imrx qvfe wfrt jcgz" },
  { email: "Linda@xemaildeliveryreport.com", password: "pndg brbk mrzs abij" },
  { email: "linda.patricia@xemaildeliveryreport.com", password: "rcua anan jztl nbxd" },
];

const outlookAccounts = [
  { email: "mahendra@xleadsconsulting.com", client_id: "29c8707e-876a-4833-8c31-4cad33a8ac0b", tenant_id: "751d98b4-f8be-4510-9ccc-97bdb4e50d02", client_secret: "wn28Q~0N-DlfWfyiSQfY.GqFLAfN4g1EuuNkhcHy" },
  { email: "lakhendra@xleadsconsulting.com", client_id: "29c8707e-876a-4833-8c31-4cad33a8ac0b", tenant_id: "751d98b4-f8be-4510-9ccc-97bdb4e50d02", client_secret: "wn28Q~0N-DlfWfyiSQfY.GqFLAfN4g1EuuNkhcHy" },
  { email: "xgrowthtech@xleadsconsulting.com", client_id: "29c8707e-876a-4833-8c31-4cad33a8ac0b", tenant_id: "751d98b4-f8be-4510-9ccc-97bdb4e50d02", client_secret: "wn28Q~0N-DlfWfyiSQfY.GqFLAfN4g1EuuNkhcHy" },
  { email: "audit@xleadoutreach.com", client_id: "29c8707e-876a-4833-8c31-4cad33a8ac0b", tenant_id: "751d98b4-f8be-4510-9ccc-97bdb4e50d02", client_secret: "wn28Q~0N-DlfWfyiSQfY.GqFLAfN4g1EuuNkhcHy" },
  { email: "brijesh@xleadoutreach.com", client_id: "29c8707e-876a-4833-8c31-4cad33a8ac0b", tenant_id: "751d98b4-f8be-4510-9ccc-97bdb4e50d02", client_secret: "wn28Q~0N-DlfWfyiSQfY.GqFLAfN4g1EuuNkhcHy" },
];

const JWT_SECRET = "your_jwt_secret_key";

// Middleware to authenticate users
const authenticateUser = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ error: "Invalid token." });
  }
};

// Register a new user
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    // Check if user already exists
    const { rows: existingUser } = await db.query(
      "SELECT * FROM Users WHERE email = $1", 
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(400).json({ error: "User already exists." });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    await db.query(
      "INSERT INTO Users (email, password) VALUES ($1, $2)", 
      [email, hashedPassword]
    );

    res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    console.error("❌ Registration error:", err.message);
    res.status(500).json({ error: "Internal server error." });
  }
});

// Login user
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    // Find the user by email
    const { rows: user } = await db.query(
      "SELECT * FROM Users WHERE email = $1", 
      [email]
    );

    if (user.length === 0) {
      return res.status(400).json({ error: "Invalid email or password." });
    }

    // Compare passwords
    const validPassword = await bcrypt.compare(password, user[0].password);
    if (!validPassword) {
      return res.status(400).json({ error: "Invalid email or password." });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user[0].id, email: user[0].email }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token, credits: user[0].credits });
  } catch (err) {
    console.error("❌ Login error:", err.message);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/user", authenticateUser, async (req, res) => {
  try {
    const { rows: user } = await db.query(
      "SELECT email, credits FROM Users WHERE id = $1", 
      [req.user.id]
    );

    if (user.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({ email: user[0].email, credits: user[0].credits });
  } catch (err) {
    console.error("❌ Error fetching user details:", err.message);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.post("/generate-test-code", authenticateUser, async (req, res) => {
  const { recipients } = req.body;
  if (!recipients) {
    return res.status(400).json({ error: "Recipients are required." });
  }

  const testCode = uuidv4();

  try {
    await db.query(
      "INSERT INTO TestRecipients (userId, testCode, recipients) VALUES ($1, $2, $3)",
      [req.user.id, testCode, recipients]
    );

    console.log(`✅ Test code ${testCode} generated for recipients: ${recipients}`);
    res.json({ testCode, recipients });
  } catch (err) {
    console.error("❌ Failed to store recipients:", err.message);
    res.status(500).json({ error: "Failed to store recipients." });
  }
});

app.post("/update-credits", authenticateUser, async (req, res) => {
  const { userId, credits } = req.body;

  if (!userId || credits === undefined) {
    return res.status(400).json({ error: "User ID and credits are required." });
  }

  try {
    const { rows: user } = await db.query(
      "SELECT * FROM Users WHERE id = $1", 
      [userId]
    );

    if (user.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    await db.query(
      "UPDATE Users SET credits = $1 WHERE id = $2", 
      [credits, userId]
    );

    res.json({ message: "User credits updated successfully.", userId, credits });
  } catch (err) {
    console.error("❌ Error updating user credits:", err.message);
    res.status(500).json({ error: "Internal server error." });
  }
});

app.post("/check-mails", authenticateUser, async (req, res) => {
  const { testCode } = req.body;
  if (!testCode) {
    return res.status(400).json({ error: "Test code is required." });
  }

  try {
    await db.query(
      "UPDATE Users SET credits = credits - 1 WHERE id = $1", 
      [req.user.id]
    );

    const { rows: recipientsRow } = await db.query(
      "SELECT recipients FROM TestRecipients WHERE testCode = $1 AND userId = $2",
      [testCode, req.user.id]
    );

    if (!recipientsRow.length) {
      return res.status(404).json({ error: "Test code not found." });
    }

    const recipients = recipientsRow[0].recipients.split(",");
    const fiveMinutesAgo = moment().subtract(5, "minutes");

    recipients.forEach((email) => {
      const trimmedEmail = email.trim();
      const gmailAccount = gmailAccounts.find(a => a.email === trimmedEmail);
      const outlookAccount = outlookAccounts.find(a => a.email === trimmedEmail);

      if (gmailAccount) checkMailbox(gmailAccount, testCode, fiveMinutesAgo, req.user.id);
      if (outlookAccount) checkOutlookMailbox(outlookAccount, testCode, req.user.id);
    });

    res.json({ message: `📬 Mailbox check initiated for ${testCode}` });
  } catch (error) {
    console.error("❌ Error checking mailboxes:", error.message);
    res.status(500).json({ error: "Internal server error", details: error.message });
  }
});

const checkMailbox = async (account, testCode, fiveMinutesAgo, userId) => {
  const config = {
    imap: {
      user: account.email,
      password: account.password,
      host: "imap.gmail.com",
      port: 993,
      tls: true,
      tlsOptions: { rejectUnauthorized: false },
      authTimeout: 5000,
    },
  };

  try {
    console.log("⏳ Waiting for 10 seconds before fetching emails...");
    await new Promise((resolve) => setTimeout(resolve, 10000));

    console.log(`🔗 Connecting to ${account.email}...`);
    const connection = await imaps.connect(config);
    console.log(`✅ Connected to ${account.email}`);

    const searchEmails = async (folderName) => {
      await connection.openBox(folderName);
      const searchCriteria = [["SINCE", fiveMinutesAgo.format("DD-MMM-YYYY")]];
      const fetchOptions = { bodies: ["HEADER", "TEXT"], markSeen: false };
      const messages = await connection.search(searchCriteria, fetchOptions);

      for (const msg of messages) {
        const body = msg.parts.find((part) => part.which === "TEXT")?.body || "";
        if (body.toLowerCase().includes(testCode.toLowerCase())) {
          const headers = msg.parts.find((part) => part.which === "HEADER")?.body || {};
          const emailContent = body;
          const emailHeaders = JSON.stringify(headers);

          await db.query(
            "INSERT INTO TestResults (userId, testCode, email, status, emailContent, emailHeaders) VALUES ($1, $2, $3, $4, $5, $6)",
            [userId, testCode, account.email, folderName === "INBOX" ? "Inbox" : "Spam", emailContent, emailHeaders]
          );

          console.log(`📨 Found test email in ${folderName} for ${account.email}`);

          if (account.email === "tmm003937@gmail.com") {
            console.log("🔍 Starting automatic analysis for tmm003937@gmail.com...");
            await analyzeEmail(account.email, testCode);
          }

          await connection.end();
          return true;
        }
      }
      return false;
    };

    const foundInInbox = await searchEmails("INBOX");
    if (foundInInbox) return;

    const foundInSpam = await searchEmails("[Gmail]/Spam");
    if (!foundInSpam) {
      await db.query(
        "INSERT INTO TestResults (userId, testCode, email, status) VALUES ($1, $2, $3, $4)",
        [userId, testCode, account.email, "Not Found"]
      );
    }

    console.log(`📨 Email for ${account.email} found in ${foundInSpam ? "SPAM" : "NOT FOUND"}`);
    await connection.end();
  } catch (error) {
    console.error(`❌ Error with ${account.email}:`, error.message);
    await db.query(
      "INSERT INTO TestResults (userId, testCode, email, status) VALUES ($1, $2, $3, $4)",
      [userId, testCode, account.email, "Error"]
    );
  }
};

const checkOutlookMailbox = async (account, testCode, userId) => {
  try {
    console.log(`📡 Fetching emails for Outlook account: ${account.email}`);
    await new Promise((resolve) => setTimeout(resolve, 15000));

    if (account.password) {
      const config = {
        imap: {
          user: account.email,
          password: account.password,
          host: "outlook.office365.com",
          port: 993,
          tls: true,
          tlsOptions: { rejectUnauthorized: false },
          authTimeout: 5000,
        },
      };

      const connection = await imaps.connect(config);
      console.log(`✅ Connected to ${account.email}`);

      const searchEmails = async (folderName) => {
        await connection.openBox(folderName);
        const searchCriteria = [["SINCE", moment().subtract(5, "minutes").format("DD-MMM-YYYY")]];
        const fetchOptions = { bodies: ["HEADER", "TEXT"], markSeen: false };
        const messages = await connection.search(searchCriteria, fetchOptions);

        for (const msg of messages) {
          const body = msg.parts.find((part) => part.which === "TEXT")?.body || "";
          if (body.toLowerCase().includes(testCode.toLowerCase())) {
            const headers = msg.parts.find((part) => part.which === "HEADER")?.body || {};
            const emailContent = body;
            const emailHeaders = JSON.stringify(headers);

            await db.query(
              "INSERT INTO TestResults (userId, testCode, email, status, emailContent, emailHeaders) VALUES ($1, $2, $3, $4, $5, $6)",
              [userId, testCode, account.email, folderName === "INBOX" ? "Inbox" : "Spam", emailContent, emailHeaders]
            );

            console.log(`📨 Found test email in ${folderName} for ${account.email}`);
            await connection.end();
            return true;
          }
        }
        return false;
      };

      const foundInInbox = await searchEmails("INBOX");
      if (foundInInbox) return;

      const foundInSpam = await searchEmails("Junk");
      if (!foundInSpam) {
        await db.query(
          "INSERT INTO TestResults (userId, testCode, email, status) VALUES ($1, $2, $3, $4)",
          [userId, testCode, account.email, "Not Found"]
        );
      }

      console.log(`📨 Email for ${account.email} found in ${foundInSpam ? "SPAM" : "NOT FOUND"}`);
      await connection.end();
    } else {
      const tokenResponse = await axios.post(
        `https://login.microsoftonline.com/${account.tenant_id}/oauth2/v2.0/token`,
        qs.stringify({
          client_id: account.client_id,
          client_secret: account.client_secret,
          scope: "https://graph.microsoft.com/.default",
          grant_type: "client_credentials",
        }),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );

      if (!tokenResponse.data.access_token) {
        throw new Error("Failed to obtain Outlook access token");
      }

      const accessToken = tokenResponse.data.access_token;
      console.log("✅ Access token obtained");

      const searchFolder = async (folderName) => {
        console.log(`🔍 Searching folder: ${folderName}`);
        await new Promise((resolve) => setTimeout(resolve, 5000));

        const messagesResponse = await axios.get(
          `https://graph.microsoft.com/v1.0/users/${account.email}/mailFolders/${folderName}/messages?$top=10`,
          { headers: { Authorization: `Bearer ${accessToken}` } }
        );

        if (!messagesResponse.data.value) {
          throw new Error(`Invalid Outlook API response for folder: ${folderName}`);
        }

        console.log(`📩 Found ${messagesResponse.data.value.length} emails in ${folderName}`);
        return messagesResponse.data.value.some((msg) => {
          const bodyContent = msg.body?.content || "";
          const $ = cheerio.load(bodyContent);
          const plainText = $("body").text().toLowerCase();
          return plainText.includes(testCode.toLowerCase());
        });
      };

      const foundInInbox = await searchFolder("inbox");
      if (foundInInbox) {
        console.log(`📩 Test email FOUND in Outlook Inbox`);
        await db.query(
          "INSERT INTO TestResults (userId, testCode, email, status) VALUES ($1, $2, $3, $4)",
          [userId, testCode, account.email, "Inbox"]
        );
        return;
      }

      const foundInJunk = await searchFolder("junkemail");
      if (foundInJunk) {
        console.log(`📩 Test email FOUND in Outlook Junk`);
        await db.query(
          "INSERT INTO TestResults (userId, testCode, email, status) VALUES ($1, $2, $3, $4)",
          [userId, testCode, account.email, "Spam"]
        );
        return;
      }

      console.log(`📩 Test email NOT FOUND in Outlook`);
      await db.query(
        "INSERT INTO TestResults (userId, testCode, email, status) VALUES ($1, $2, $3, $4)",
        [userId, testCode, account.email, "Not Found"]
      );
    }
  } catch (error) {
    console.error(`❌ Error fetching Outlook emails:`, error.message);
    await db.query(
      "INSERT INTO TestResults (userId, testCode, email, status) VALUES ($1, $2, $3, $4)",
      [userId, testCode, account.email, "Error"]
    );
  }
};

const extractIPFromHeaders = (headers) => {
  const receivedHeaders = headers["received"] || [];
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  for (const header of receivedHeaders) {
    const match = header.match(ipRegex);
    if (match) return match[0];
  }
  return null;
};

const checkBlacklists = async (ipOrDomain) => {
  const blacklists = [
    { name: "Spamhaus (ZEN)", dns: "zen.spamhaus.org" },
    { name: "Spamhaus (SBL)", dns: "sbl.spamhaus.org" },
    { name: "Spamhaus (XBL)", dns: "xbl.spamhaus.org" },
    { name: "Spamhaus (DBL)", dns: "dbl.spamhaus.org" },
    { name: "Barracuda", dns: "b.barracudacentral.org" },
  ];

  const results = [];
  for (const blacklist of blacklists) {
    try {
      const response = await fetch(
        `https://dns.google/resolve?name=${ipOrDomain}.${blacklist.dns}&type=A`
      );
      const data = await response.json();
      if (data.Answer && data.Answer.length > 0) {
        results.push({ blacklist: blacklist.name, listed: true, details: data.Answer });
      } else {
        results.push({ blacklist: blacklist.name, listed: false, details: null });
      }
    } catch (error) {
      console.error(`❌ Error checking blacklist ${blacklist.name}:`, error.message);
      results.push({ blacklist: blacklist.name, listed: false, details: null });
    }
  }
  return results;
};

const readSpamWords = () => {
  return new Promise((resolve, reject) => {
    const spamWords = [];
    fs.createReadStream("spam_words.csv")
      .pipe(csv())
      .on("data", (row) => spamWords.push(Object.values(row)[0]))
      .on("end", () => {
        console.log("✅ Spam words loaded from CSV");
        resolve(spamWords);
      })
      .on("error", (error) => {
        console.error("❌ Error reading spam words CSV:", error.message);
        reject(error);
      });
  });
};

const checkSpamWordsLocally = async (htmlContent) => {
  try {
    const $ = cheerio.load(htmlContent);
    const plainText = $("body").text().toLowerCase();
    const spamWords = await readSpamWords();
    const foundSpamWords = spamWords.filter((word) =>
      plainText.includes(word.toLowerCase())
    );
    return {
      spamWordsFound: foundSpamWords.length > 0,
      spamWordsList: foundSpamWords,
    };
  } catch (error) {
    console.error("❌ Error checking spam words locally:", error.message);
    return {
      spamWordsFound: false,
      spamWordsList: [],
    };
  }
};

app.get("/analyze-email/:testCode", authenticateUser, async (req, res) => {
  const { testCode } = req.params;
  try {
    const { rows: testRecipient } = await db.query(
      "SELECT * FROM TestRecipients WHERE testCode = $1 AND userId = $2",
      [testCode, req.user.id]
    );

    if (testRecipient.length === 0) {
      return res.status(404).json({ error: "Test code not found" });
    }

    const recipients = testRecipient[0].recipients.split(",");
    let targetEmail = null;
    for (const email of recipients) {
      const trimmedEmail = email.trim();
      if (trimmedEmail.includes("@gmail.com")) {
        targetEmail = trimmedEmail;
        break;
      }
    }

    if (!targetEmail) {
      return res.status(400).json({ error: "No suitable Gmail account found for analysis" });
    }

    const emailDetails = await analyzeEmail(targetEmail, testCode);
    res.json(emailDetails);
  } catch (error) {
    console.error("❌ Error analyzing email:", error.message);
    res.status(500).json({ error: "Internal server error", details: error.message });
  }
});

const analyzeEmail = async (email, testCode) => {
  try {
    const { rows: result } = await db.query(
      "SELECT id, emailContent, emailHeaders FROM TestResults WHERE email = $1 AND testCode = $2",
      [email, testCode]
    );

    if (!result.length || !result[0].emailcontent || !result[0].emailheaders) {
      return { error: "No email content found for analysis." };
    }

    const testResultId = result[0].id;
    const emailContent = result[0].emailcontent;
    const emailHeaders = JSON.parse(result[0].emailheaders);

    const subject = Array.isArray(emailHeaders.subject) ? emailHeaders.subject[0] : (emailHeaders.subject || "No Subject");
    const from = Array.isArray(emailHeaders.from) ? emailHeaders.from[0] : (emailHeaders.from || "Unknown Sender");
    const date = Array.isArray(emailHeaders.date) ? emailHeaders.date[0] : (emailHeaders.date || "Unknown Date");

    const dkim = extractAuthResult(emailHeaders, "dkim");
    const spf = extractAuthResult(emailHeaders, "spf");
    const dmarc = extractAuthResult(emailHeaders, "dmarc");

    const $ = cheerio.load(emailContent);
    const plainTextContent = $("body").text();
    const linkRegex = /https?:\/\/[^\s"<>()]+/g;
    const links = plainTextContent.match(linkRegex) || [];
    const validLinks = [...new Set(links)].filter((link) => {
      try {
        new URL(link);
        return true;
      } catch (err) {
        return false;
      }
    });

    const checkLink = async (link) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        let response = await fetch(link, { method: "HEAD", signal: controller.signal });
        clearTimeout(timeout);
        if (!response.ok) {
          response = await fetch(link, { method: "GET", signal: controller.signal });
        }
        return { link, status: response.ok ? "OK" : "Broken" };
      } catch (error) {
        return { link, status: "Broken", error: error.message || "Request failed" };
      }
    };

    const linkStatuses = await Promise.all(validLinks.map(checkLink));
    const domain = from.split('@')[1]?.replace(/[^a-zA-Z0-9.-]/g, '');
    const receivedHeaders = emailHeaders["received"] || [];
    const receivedHeader = Array.isArray(receivedHeaders) ? receivedHeaders.join(" ") : receivedHeaders;
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    const ipAddress = receivedHeader.match(ipRegex)?.[0] || null;

    let mxRecordsExist = false;
    let mxRecordsData = null;
    if (domain) {
      try {
        const response = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
        const data = await response.json();
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
          mxRecordsExist = true;
          mxRecordsData = data.Answer;
        }
      } catch (error) {
        console.error(`❌ Error checking MX records for ${domain}:`, error.message);
      }
    }

    const domainBlacklistResults = domain ? await checkBlacklists(domain) : [];
    const ipBlacklistResults = ipAddress ? await checkBlacklists(ipAddress) : [];
    const spamWordAnalysis = await checkSpamWordsLocally(emailContent);

    await db.query(
      `INSERT INTO EmailAnalysis (
        testResultId, subject, fromEmail, date, authentication, 
        domainBlacklistCheck, ipBlacklistCheck, linkStatuses, 
        spamWordAnalysis, emailContent, mxRecords, mxRecordsData
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        testResultId,
        subject,
        from,
        date,
        JSON.stringify({ dkim, spf, dmarc, mxRecords: mxRecordsExist ? "pass" : "fail" }),
        JSON.stringify(domainBlacklistResults),
        JSON.stringify(ipBlacklistResults),
        JSON.stringify(linkStatuses),
        JSON.stringify(spamWordAnalysis),
        emailContent,
        mxRecordsExist ? "Exists" : "Does not exist",
        JSON.stringify(mxRecordsData),
      ]
    );

    return {
      subject,
      from,
      date,
      authentication: { dkim, spf, dmarc },
      content: emailContent,
      linkCount: linkStatuses.length,
      linkStatuses,
      mxRecords: mxRecordsExist ? "Exists" : "Does not exist",
      mxRecordsData,
      domainBlacklistResults,
      ipBlacklistResults,
      spamWords: spamWordAnalysis,
    };
  } catch (error) {
    console.error(`❌ Error analyzing email for ${email}:`, error.message);
    return { error: error.message };
  }
};

const extractAuthResult = (header, type) => {
  const authHeader = header["authentication-results"] || [];
  const authResults = Array.isArray(authHeader) ? authHeader.join(" ") : authHeader;
  const match = authResults.match(new RegExp(`${type}=([a-zA-Z]+)`, "i"));
  return match ? match[1] : "Unknown";
};

app.get("/get-previous-tests", authenticateUser, async (req, res) => {
  try {
    // Fetch all test recipients for the logged-in user
    const { rows: testRecipients } = await db.query(
      "SELECT * FROM TestRecipients WHERE userId = $1 ORDER BY timestamp DESC", 
      [req.user.id]
    );

    // Fetch results and analysis for each test recipient
    const previousTests = await Promise.all(
      testRecipients.map(async (recipient) => {
        // Fetch ALL test results for the current test code
        const { rows: results } = await db.query(
          "SELECT * FROM TestResults WHERE testCode = $1", 
          [recipient.testcode]
        );

        // Process results while maintaining order
        const orderedResults = [];
        
        // First add pro-gmail accounts in order
        const proGmailEmails = [
          'Patricia@emaildeliveryreport.com',
          'l.Patricia@emaildeliveryreport.net',
          'lindaPatricia@xemaildeliveryreport.com',
          'Linda@xemaildeliveryreport.com',
          'linda.patricia@xemaildeliveryreport.com'
        ];
        
        // Then add pro-outlook accounts in order
        const proOutlookEmails = [
          'brijesh@xleadoutreach.com',
          'mahendra@xleadsconsulting.com',
          'lakhendra@xleadsconsulting.com',
          'xgrowthtech@xleadsconsulting.com',
          'audit@xleadoutreach.com'
        ];
        
        // Then add regular gmail accounts in order
        const gmailEmails = [
          'tmm003937@gmail.com',
          'mta872679@gmail.com',
          'houseisitter@gmail.com',
          'malaikaarora983475@gmail.com',
          'rheadutta096@gmail.com'
        ];

        // Combine all emails in the desired order
        const allEmailsInOrder = [...proGmailEmails, ...proOutlookEmails, ...gmailEmails];

        // Process results in the predefined order
        for (const email of allEmailsInOrder) {
          const result = results.find(r => r.email === email);
          if (result) {
            const { rows: analysis } = await db.query(
              "SELECT * FROM EmailAnalysis WHERE testResultId = $1", 
              [result.id]
            );

            const safeParse = (value) => {
              if (typeof value === 'string') {
                try {
                  return JSON.parse(value);
                } catch (error) {
                  console.error("Failed to parse JSON:", value);
                  return null;
                }
              }
              return value;
            };

            orderedResults.push({
              email: result.email,
              esp: espMapping[result.email] || 'unknown',
              status: result.status,
              subject: analysis[0]?.subject || "No Subject",
              from: analysis[0]?.fromemail || "Unknown Sender", // Changed to lowercase to match PostgreSQL
              date: analysis[0]?.date || "Unknown Date",
              linkCount: analysis[0]?.linkstatuses ? safeParse(analysis[0].linkstatuses).length : 0, // Changed to lowercase
              linkStatuses: analysis[0]?.linkstatuses ? safeParse(analysis[0].linkstatuses) : [], // Changed to lowercase
              domainBlacklistCheck: analysis[0]?.domainblacklistcheck ? safeParse(analysis[0].domainblacklistcheck) : [], // Changed to lowercase
              ipBlacklistCheck: analysis[0]?.ipblacklistcheck ? safeParse(analysis[0].ipblacklistcheck) : [], // Changed to lowercase
              spamWordAnalysis: analysis[0]?.spamwordanalysis ? safeParse(analysis[0].spamwordanalysis) : {}, // Changed to lowercase
              mxRecords: analysis[0]?.mxrecords || null, // Changed to lowercase
              mxRecordsData: analysis[0]?.mxrecordsdata ? safeParse(analysis[0].mxrecordsdata) : null, // Changed to lowercase
              analysis: analysis[0] || null,
            });
          }
        }

        return {
          testCode: recipient.testcode, // Changed to lowercase to match PostgreSQL
          sendingEmail: req.user.email,
          results: orderedResults,
        };
      })
    );

    res.json(previousTests);
  } catch (error) {
    console.error("❌ Error fetching previous tests:", error.message);
    res.status(500).json({ error: "Internal server error", details: error.message });
  }
});

app.get("/get-latest-analysis/:testCode", authenticateUser, async (req, res) => {
  const { testCode } = req.params;
  console.log("Fetching analysis for testCode:", testCode);

  try {
    // Fetch the latest analysis directly for the given test code
    const { rows: analysis } = await db.query(
      `SELECT ea.* 
       FROM EmailAnalysis ea
       JOIN TestResults tr ON ea.testResultId = tr.id
       WHERE tr.testCode = $1
       ORDER BY ea.timestamp DESC
       LIMIT 1`,
      [testCode]
    );

    if (analysis.length === 0) {
      console.log("No analysis found for testCode:", testCode);
      return res.status(404).json({ error: "No analysis found for this test code." });
    }

    console.log("Analysis data found:", analysis[0]);

    // Helper function to safely parse JSON or return the original value
    const safeParse = (value) => {
      if (typeof value === 'string') {
        try {
          return JSON.parse(value);
        } catch (error) {
          console.error("Failed to parse JSON:", value);
          return null;
        }
      }
      return value;
    };

    // Parse JSON fields if they are stored as strings
    const parsedAnalysis = {
      ...analysis[0],
      authentication: safeParse(analysis[0].authentication),
      domainblacklistcheck: safeParse(analysis[0].domainblacklistcheck), // Changed to lowercase
      ipblacklistcheck: safeParse(analysis[0].ipblacklistcheck), // Changed to lowercase
      linkstatuses: safeParse(analysis[0].linkstatuses), // Changed to lowercase
      spamwordanalysis: safeParse(analysis[0].spamwordanalysis), // Changed to lowercase
      mxrecordsdata: safeParse(analysis[0].mxrecordsdata), // Changed to lowercase
    };

    // Return the latest analysis
    res.json(parsedAnalysis);
  } catch (error) {
    console.error("❌ Error fetching latest analysis:", error.message);
    res.status(500).json({ error: "Internal server error", details: error.message });
  }
});

// SSE endpoint for live results
app.get("/results-stream/:testCode", (req, res) => {
  const { testCode } = req.params;
  const token = req.query.token;

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id;

    // Set headers for SSE
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    // Keep track of sent results to avoid duplicates
    const sentResults = new Set();

    const sendUpdate = (email, status) => {
      const resultKey = `${email}:${status}`;
      if (!sentResults.has(resultKey)) {
        res.write(`data: ${JSON.stringify({ email, status })}\n\n`);
        sentResults.add(resultKey);
        console.log(`📤 Sent update for ${email}: ${status}`);
      }
    };

    const checkForUpdates = () => {
      db.query(
        "SELECT email, status FROM TestResults WHERE testCode = $1 AND userId = $2",
        [testCode, userId],
        (err, { rows: results }) => {
          if (err) {
            console.error("❌ Database error:", err.message);
            return;
          }

          console.log(`🔍 Found ${results.length} results in database check`);
          results.forEach((result) => {
            sendUpdate(result.email, result.status);
          });
        }
      );
    };

    // Initial check
    checkForUpdates();

    // Check for updates every 2 seconds
    const interval = setInterval(checkForUpdates, 2000);

    // Cleanup on client disconnect
    req.on("close", () => {
      clearInterval(interval);
      res.end();
      console.log('🚪 Client disconnected from SSE stream');
    });

  } catch (err) {
    console.error("SSE setup error:", err);
    res.status(400).json({ error: "Invalid token." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Backend running on port ${PORT}`));
