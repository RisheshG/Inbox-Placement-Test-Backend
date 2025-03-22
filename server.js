const express = require("express");
const { v4: uuidv4 } = require("uuid");
const imaps = require("imap-simple");
const mysql = require("mysql2");
const moment = require("moment");
const axios = require("axios");
const qs = require("querystring");
const cheerio = require("cheerio");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const csv = require("csv-parser");


const app = express();
app.use(express.json({ limit: "10mb" })); // Fix JSON parsing issue
app.use(cors()); // Enable CORS

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Rishesh@123",
  database: "inboxPlacement",
});

db.connect((err) => {
  if (err) console.error("❌ Database connection failed:", err.message);
  else console.log("✅ Connected to MySQL database.");
});

// Create necessary tables
db.query(`
  CREATE TABLE IF NOT EXISTS Users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    credits INT DEFAULT 10,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

db.query(`
  CREATE TABLE IF NOT EXISTS TestResults (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT,
    testCode VARCHAR(255),
    email VARCHAR(255),
    status VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES Users(id)
  )
`);

db.query(`
  CREATE TABLE IF NOT EXISTS TestRecipients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT,
    testCode VARCHAR(255),
    recipients TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES Users(id)
  )
`);

db.query(`
  CREATE TABLE IF NOT EXISTS EmailAnalysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    testResultId INT,
    authentication JSON,
    domainBlacklistCheck JSON,
    ipBlacklistCheck JSON,
    linkStatuses JSON,
    spamWordAnalysis JSON,
    emailContent TEXT,
    FOREIGN KEY (testResultId) REFERENCES TestResults(id)
  )
`);

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


const JWT_SECRET = "your_jwt_secret_key"; // Replace with a secure key

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
    const [existingUser] = await db
      .promise()
      .query("SELECT * FROM Users WHERE email = ?", [email]);

    if (existingUser.length > 0) {
      return res.status(400).json({ error: "User already exists." });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    await db
      .promise()
      .query("INSERT INTO Users (email, password) VALUES (?, ?)", [
        email,
        hashedPassword,
      ]);

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
    const [user] = await db
      .promise()
      .query("SELECT * FROM Users WHERE email = ?", [email]);

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

// Add this endpoint to your backend code
app.get("/user", authenticateUser, async (req, res) => {
  try {
    // Fetch the user's details from the database
    const [user] = await db
      .promise()
      .query("SELECT email, credits FROM Users WHERE id = ?", [req.user.id]);

    if (user.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    // Return the user's email and credits
    res.json({ email: user[0].email, credits: user[0].credits });
  } catch (err) {
    console.error("❌ Error fetching user details:", err.message);
    res.status(500).json({ error: "Internal server error." });
  }
});

// Generate a test code and store recipients
app.post("/generate-test-code", authenticateUser, (req, res) => {
  const { recipients } = req.body; // Expecting a comma-separated string of emails
  if (!recipients) {
    return res.status(400).json({ error: "Recipients are required." });
  }

  const testCode = uuidv4();

  // Store the test code and recipients in the database
  db.query(
    "INSERT INTO TestRecipients (userId, testCode, recipients) VALUES (?, ?, ?)",
    [req.user.id, testCode, recipients],
    (err) => {
      if (err) {
        console.error("❌ Failed to store recipients:", err.message);
        return res.status(500).json({ error: "Failed to store recipients." });
      }

      console.log(`✅ Test code ${testCode} generated for recipients: ${recipients}`);
      res.json({ testCode, recipients });
    }
  );
});

// Update user credits
app.post("/update-credits", authenticateUser, async (req, res) => {
  const { userId, credits } = req.body;

  if (!userId || credits === undefined) {
    return res.status(400).json({ error: "User ID and credits are required." });
  }

  try {
    // Check if the user exists
    const [user] = await db
      .promise()
      .query("SELECT * FROM Users WHERE id = ?", [userId]);

    if (user.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    // Update the user's credits
    await db
      .promise()
      .query("UPDATE Users SET credits = ? WHERE id = ?", [credits, userId]);

    res.json({ message: "User credits updated successfully.", userId, credits });
  } catch (err) {
    console.error("❌ Error updating user credits:", err.message);
    res.status(500).json({ error: "Internal server error." });
  }
});

// Check mailboxes for results
app.post("/check-mails", authenticateUser, async (req, res) => {
  const { testCode } = req.body;
  if (!testCode) {
    return res.status(400).json({ error: "Test code is required." });
  }

  try {
    // Deduct 1 credit
    await db
      .promise()
      .query("UPDATE Users SET credits = credits - 1 WHERE id = ?", [req.user.id]);

    // Fetch recipients for the test code
    const [recipientsRow] = await db
      .promise()
      .query("SELECT recipients FROM TestRecipients WHERE testCode = ? AND userId = ?", [
        testCode,
        req.user.id,
      ]);

    if (!recipientsRow.length) {
      return res.status(404).json({ error: "Test code not found." });
    }

    const recipients = recipientsRow[0].recipients.split(",");
    const fiveMinutesAgo = moment().subtract(5, "minutes");

    // Process mailbox checks asynchronously
    recipients.forEach((email) => {
      const trimmedEmail = email.trim();

      // Check if the email is a Gmail account
      const gmailAccount = gmailAccounts.find((account) => account.email === trimmedEmail);
      if (gmailAccount) {
        checkMailbox(gmailAccount, testCode, fiveMinutesAgo, req.user.id); // Use IMAP logic for Gmail
      }

      // Check if the email is an Outlook account
      const outlookAccount = outlookAccounts.find((account) => account.email === trimmedEmail);
      if (outlookAccount) {
        checkOutlookMailbox(outlookAccount, testCode, req.user.id); // Use Outlook-specific logic
      }
    });

    res.json({ message: `📬 Mailbox check initiated for ${testCode}` });
  } catch (error) {
    console.error("❌ Error checking mailboxes:", error.message);
    res.status(500).json({ error: "Internal server error", details: error.message });
  }
});

// Function to check mailbox for a single email (Gmail)
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
    // Add a 10-second delay before connecting to the IMAP server
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

          // Store the email content and headers in the database
          await db.promise().query(
            "INSERT INTO TestResults (userId, testCode, email, status, emailContent, emailHeaders) VALUES (?, ?, ?, ?, ?, ?)",
            [userId, testCode, account.email, folderName === "INBOX" ? "Inbox" : "Spam", emailContent, emailHeaders]
          );

          console.log(`📨 Found test email in ${folderName} for ${account.email}`);

          // Trigger analysis automatically for tmm003937@gmail.com
          if (account.email === "tmm003937@gmail.com") {
            console.log("🔍 Starting automatic analysis for tmm003937@gmail.com...");
            await analyzeEmail(account.email, testCode); // Start analysis
          }

          await connection.end();
          return true;
        }
      }
      return false;
    };

    const foundInInbox = await searchEmails("INBOX");
    if (foundInInbox) {
      return;
    }

    const foundInSpam = await searchEmails("[Gmail]/Spam");
    if (!foundInSpam) {
      await db.promise().query(
        "INSERT INTO TestResults (userId, testCode, email, status) VALUES (?, ?, ?, ?)",
        [userId, testCode, account.email, "Not Found"]
      );
    }

    console.log(`📨 Email for ${account.email} found in ${foundInSpam ? "SPAM" : "NOT FOUND"}`);
    await connection.end();
  } catch (error) {
    console.error(`❌ Error with ${account.email}:`, error.message);
    await db.promise().query(
      "INSERT INTO TestResults (userId, testCode, email, status) VALUES (?, ?, ?, ?)",
      [userId, testCode, account.email, "Error"]
    );
  }
};

// Function to check mailbox for Outlook
const checkOutlookMailbox = async (account, testCode, userId) => {
  try {
    console.log(`📡 Fetching emails for Outlook account: ${account.email}`);

    // Wait for 5 seconds before proceeding
    console.log("⏳ Waiting for 5 seconds before fetching emails...");
    await new Promise((resolve) => setTimeout(resolve, 10000));

    // Get access token
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

    // Function to search emails in a specific folder
    const searchFolder = async (folderName) => {
      console.log(`🔍 Searching folder: ${folderName}`);

      // Add a 5-second delay before searching this folder
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

    // Check Inbox folder (with 5-second delay)
    const foundInInbox = await searchFolder("inbox");

    if (foundInInbox) {
      console.log(`📩 Test email FOUND in Outlook Inbox`);
      db.query(
        "INSERT INTO TestResults (userId, testCode, email, status) VALUES (?, ?, ?, ?)",
        [userId, testCode, account.email, "Inbox"]
      );
      return;
    }

    // Check Junk folder (with 5-second delay)
    const foundInJunk = await searchFolder("junkemail");
    if (foundInJunk) {
      console.log(`📩 Test email FOUND in Outlook Junk`);
      db.query(
        "INSERT INTO TestResults (userId, testCode, email, status) VALUES (?, ?, ?, ?)",
        [userId, testCode, account.email, "Spam"]
      );
      return;
    }

    // If not found in either folder
    console.log(`📩 Test email NOT FOUND in Outlook`);
    db.query(
      "INSERT INTO TestResults (userId, testCode, email, status) VALUES (?, ?, ?, ?)",
      [userId, testCode, account.email, "Not Found"]
    );
  } catch (error) {
    console.error(`❌ Error fetching Outlook emails:`, error.message);
    db.query(
      "INSERT INTO TestResults (userId, testCode, email, status) VALUES (?, ?, ?, ?)",
      [userId, testCode, account.email, "Error"]
    );
  }
};

const extractIPFromHeaders = (headers) => {
  const receivedHeaders = headers["received"] || [];
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/; // Regex to match IPv4 addresses

  for (const header of receivedHeaders) {
    const match = header.match(ipRegex);
    if (match) {
      return match[0]; // Return the first IP address found
    }
  }

  return null; // No IP address found
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
      .on("data", (row) => {
        // Assuming each row has a single column with the spam word
        spamWords.push(Object.values(row)[0]);
      })
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

// Function to check spam words in the email content
const checkSpamWordsLocally = async (htmlContent) => {
  try {
    // Load the HTML content using cheerio
    const $ = cheerio.load(htmlContent);

    // Extract plain text content from the HTML
    const plainText = $("body").text().toLowerCase(); // Convert to lowercase for case-insensitive matching

    // Read spam words from the CSV file
    const spamWords = await readSpamWords();

    // Check if any spam words are present in the plain text
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

// Get email analysis (headers and content)
app.get("/analyze-email/:testCode", authenticateUser, async (req, res) => {
  const { testCode } = req.params;

  try {
    // Check if the test code exists and belongs to the user
    const [testRecipient] = await db
      .promise()
      .query("SELECT * FROM TestRecipients WHERE testCode = ? AND userId = ?", [
        testCode,
        req.user.id,
      ]);

    if (testRecipient.length === 0) {
      return res.status(404).json({ error: "Test code not found" });
    }

    const recipients = testRecipient[0].recipients.split(",");

    // We'll analyze the first Gmail account in the recipients list
    let targetEmail = null;
    for (const email of recipients) {
      const trimmedEmail = email.trim();
      if (trimmedEmail !== outlookAccount.email && trimmedEmail.includes("@gmail.com")) {
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

// Function to analyze email and extract relevant information
const analyzeEmail = async (email, testCode) => {
  try {
    // Retrieve stored email content and headers from the database
    const [result] = await db
      .promise()
      .query("SELECT id, emailContent, emailHeaders FROM TestResults WHERE email = ? AND testCode = ?", [
        email,
        testCode,
      ]);

    if (!result.length || !result[0].emailContent || !result[0].emailHeaders) {
      return { error: "No email content found for analysis." };
    }

    const testResultId = result[0].id;
    const emailContent = result[0].emailContent;
    const emailHeaders = JSON.parse(result[0].emailHeaders);

    // Extract subject, from, and date from headers
    const subject = Array.isArray(emailHeaders.subject) ? emailHeaders.subject[0] : (emailHeaders.subject || "No Subject");
    const from = Array.isArray(emailHeaders.from) ? emailHeaders.from[0] : (emailHeaders.from || "Unknown Sender");
    const date = Array.isArray(emailHeaders.date) ? emailHeaders.date[0] : (emailHeaders.date || "Unknown Date");

    // Extract authentication headers
    const dkim = extractAuthResult(emailHeaders, "dkim");
    const spf = extractAuthResult(emailHeaders, "spf");
    const dmarc = extractAuthResult(emailHeaders, "dmarc");

    // Extract plain text content from the email using Cheerio
    const $ = cheerio.load(emailContent);
    const plainTextContent = $("body").text(); // Extract plain text content

    // Extract links from the plain text content
    const linkRegex = /https?:\/\/[^\s"<>()]+/g;
    const links = plainTextContent.match(linkRegex) || [];

    // Filter out invalid links and remove duplicates
    const validLinks = [...new Set(links)].filter((link) => {
      try {
        new URL(link); // Validate URL
        return true;
      } catch (err) {
        return false; // Invalid URL
      }
    });

    // Check if links are broken
    const checkLink = async (link) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000); // Set a timeout of 5 seconds

        let response = await fetch(link, { method: "HEAD", signal: controller.signal });

        clearTimeout(timeout);

        if (!response.ok) {
          // If HEAD fails, try a GET request
          response = await fetch(link, { method: "GET", signal: controller.signal });
        }

        return { link, status: response.ok ? "OK" : "Broken" };
      } catch (error) {
        return { link, status: "Broken", error: error.message || "Request failed" };
      }
    };

    const linkStatuses = await Promise.all(validLinks.map(checkLink));

    console.log(linkStatuses);

    // Extract and clean domain from the "from" field
    const domain = from.split('@')[1]?.replace(/[^a-zA-Z0-9.-]/g, ''); // Remove invalid characters

    // Extract IP address from the "Received" header
    const receivedHeaders = emailHeaders["received"] || [];
    const receivedHeader = Array.isArray(receivedHeaders) ? receivedHeaders.join(" ") : receivedHeaders;
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/; // Regex to match an IP address
    const ipAddress = receivedHeader.match(ipRegex)?.[0] || null;

    // Check MX records for the domain using dns.google API
    let mxRecordsExist = false;
    let mxRecordsData = null;

    if (domain) {
      console.log(`🔍 Checking MX records for domain: ${domain}`);

      try {
        const response = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
        const data = await response.json();

        console.log(`📄 Data returned for MX records of ${domain}:`, data);

        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
          mxRecordsExist = true;
          mxRecordsData = data.Answer;
        } else if (data.Status === 3) {
          console.log(`❌ Domain does not exist (NXDOMAIN): ${domain}`);
        } else {
          console.log(`❌ No MX records found for domain: ${domain}`);
        }
      } catch (error) {
        console.error(`❌ Error checking MX records for ${domain}:`, error.message);
      }
    } else {
      console.log(`❌ Invalid domain extracted from "from" field: ${from}`);
    }

    // Check blacklists for the domain
    const domainBlacklistResults = domain ? await checkBlacklists(domain) : [];

    // Check blacklists for the IP address
    const ipBlacklistResults = ipAddress ? await checkBlacklists(ipAddress) : [];

    // Check for spam words using the local CSV file
    const spamWordAnalysis = await checkSpamWordsLocally(emailContent);

    // Store the analysis data in the EmailAnalysis table
    await db.promise().query(
      "INSERT INTO EmailAnalysis (testResultId, subject, fromEmail, date, authentication, domainBlacklistCheck, ipBlacklistCheck, linkStatuses, spamWordAnalysis, emailContent, mxRecords, mxRecordsData, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [
        testResultId,
        subject,
        from,
        date,
        JSON.stringify({ dkim, spf, dmarc, mxRecords: mxRecordsExist ? "pass" : "fail" }), // Include MX record status in authentication
        JSON.stringify(domainBlacklistResults),
        JSON.stringify(ipBlacklistResults),
        JSON.stringify(linkStatuses),
        JSON.stringify(spamWordAnalysis),
        emailContent,
        mxRecordsExist ? "Exists" : "Does not exist", // Add MX record status as a separate field
        JSON.stringify(mxRecordsData), // Add MX records data
        new Date(),
      ]
    );

    console.log(`📊 Analysis complete for email with subject: ${subject}`);

    return {
      subject,
      from,
      date,
      authentication: { dkim, spf, dmarc },
      content: emailContent,
      linkCount: linkStatuses.length,
      linkStatuses,
      mxRecords: mxRecordsExist ? "Exists" : "Does not exist", // Add MX record status
      mxRecordsData: mxRecordsData, // Include the raw MX records data
      domainBlacklistResults, // Include detailed domain blacklist results
      ipBlacklistResults, // Include detailed IP blacklist results
      spamWords: spamWordAnalysis, // Include spam word analysis results
    };
  } catch (error) {
    console.error(`❌ Error analyzing email for ${email}:`, error.message);
    return { error: error.message };
  }
};

// Helper function to extract SPF, DKIM, and DMARC results from headers
const extractAuthResult = (header, type) => {
  const authHeader = header["authentication-results"] || [];
  const authResults = Array.isArray(authHeader) ? authHeader.join(" ") : authHeader;

  const match = authResults.match(new RegExp(`${type}=([a-zA-Z]+)`, "i"));
  return match ? match[1] : "Unknown";
};

app.get("/get-previous-tests", authenticateUser, async (req, res) => {
  try {
    // Fetch all test recipients for the logged-in user
    const [testRecipients] = await db
      .promise()
      .query("SELECT * FROM TestRecipients WHERE userId = ? ORDER BY timestamp DESC", [req.user.id]);

    // Fetch results and analysis for each test recipient
    const previousTests = await Promise.all(
      testRecipients.map(async (recipient) => {
        // Fetch test results for the current test code
        const [results] = await db
          .promise()
          .query("SELECT * FROM TestResults WHERE testCode = ?", [recipient.testCode]);

        // Fetch analysis for each test result
        const resultsWithAnalysis = await Promise.all(
          results.map(async (result) => {
            const [analysis] = await db
              .promise()
              .query("SELECT * FROM EmailAnalysis WHERE testResultId = ?", [result.id]);
        
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
              return value; // Return the original value if it's already an object
            };
        
            return {
              email: result.email,
              status: result.status,
              subject: analysis[0]?.subject || "No Subject",
              from: analysis[0]?.fromEmail || "Unknown Sender",
              date: analysis[0]?.date || "Unknown Date",
              linkCount: analysis[0]?.linkStatuses ? safeParse(analysis[0].linkStatuses).length : 0,
              linkStatuses: analysis[0]?.linkStatuses ? safeParse(analysis[0].linkStatuses) : [], // Add link statuses
              domainBlacklistCheck: analysis[0]?.domainBlacklistCheck ? safeParse(analysis[0].domainBlacklistCheck) : [],
              ipBlacklistCheck: analysis[0]?.ipBlacklistCheck ? safeParse(analysis[0].ipBlacklistCheck) : [],
              spamWordAnalysis: analysis[0]?.spamWordAnalysis ? safeParse(analysis[0].spamWordAnalysis) : {},
              mxRecords: analysis[0]?.mxRecords || null, // Add MX record status
              mxRecordsData: analysis[0]?.mxRecordsData ? safeParse(analysis[0].mxRecordsData) : null, // Add MX records data
              analysis: analysis[0] || null, // Include analysis data for each result
            };
          })
        );

        return {
          testCode: recipient.testCode,
          sendingEmail: req.user.email, // Assuming the sending email is the user's email
          results: resultsWithAnalysis, // Include results with analysis
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
    const [analysis] = await db
      .promise()
      .query(
        `SELECT ea.* 
         FROM EmailAnalysis ea
         JOIN TestResults tr ON ea.testResultId = tr.id
         WHERE tr.testCode = ?
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
      return value; // Return the original value if it's already an object
    };

    // Parse JSON fields if they are stored as strings
    const parsedAnalysis = {
      ...analysis[0],
      authentication: safeParse(analysis[0].authentication),
      domainBlacklistCheck: safeParse(analysis[0].domainBlacklistCheck),
      ipBlacklistCheck: safeParse(analysis[0].ipBlacklistCheck),
      linkStatuses: safeParse(analysis[0].linkStatuses),
      spamWordAnalysis: safeParse(analysis[0].spamWordAnalysis),
      mxRecordsData: safeParse(analysis[0].mxRecordsData),
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
  const token = req.query.token; // Get token from query parameter

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

    // Function to send updates to the client
    const sendUpdate = (email, status) => {
      res.write(`data: ${JSON.stringify({ email, status })}\n\n`);
    };

    // Listen for new results in the database
    const checkForUpdates = () => {
      db.query(
        "SELECT email, status FROM TestResults WHERE testCode = ? AND userId = ?",
        [testCode, userId],
        (err, results) => {
          if (err) {
            console.error("❌ Database error:", err.message);
            return;
          }

          // Send updates for each result
          results.forEach((result) => {
            sendUpdate(result.email, result.status);
          });
        }
      );
    };

    // Check for updates every 2 seconds
    const interval = setInterval(checkForUpdates, 2000);

    // Cleanup on client disconnect
    req.on("close", () => {
      clearInterval(interval);
      res.end();
    });
  } catch (err) {
    res.status(400).json({ error: "Invalid token." });
  }
});

app.listen(3000, () => console.log("🚀 Backend running on port 3000"));
