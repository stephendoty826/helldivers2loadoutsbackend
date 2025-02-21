const express = require("express");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const crypto = require('crypto');
const dotenv = require("dotenv");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5050;

// Middleware
app.use(express.json());

// Open SQLite database
const dbPromise = open({
  filename: "tokens.db",
  driver: sqlite3.Database,
});

// Initialize database
async function initDB() {
  const db = await dbPromise;
  await db.exec(`
    CREATE TABLE IF NOT EXISTS tokens (
      user_email TEXT PRIMARY KEY,
      access_token TEXT,
      refresh_token TEXT,
      iv_access_token TEXT,
      iv_refresh_token TEXT,
      key_access_token TEXT,
      key_refresh_token TEXT
    )
  `);
}
initDB();

// Encrypt function for security
const encryptToken = (token, secretKey) => {
  const iv = crypto.randomBytes(16); // Initialization vector for AES
  const key = crypto.createHash('sha256').update(secretKey).digest(); // Ensure 32-byte key
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const ivHex = iv.toString('hex');
  return { encryptedToken: encrypted, iv: ivHex, key: key.toString("hex") };
};

const decryptToken = (encryptedToken, keyHex, ivHex) => {
  const iv = Buffer.from(ivHex, 'hex');
  const key = Buffer.from(keyHex, 'hex')
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  console.log(iv, key, decipher)
  let decrypted = decipher.update(encryptedToken, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// Store Dropbox token
app.post("/save-token", async (req, res) => {
  const { userEmail, accessToken, refreshToken } = req.body;

  if (!userEmail || !accessToken || !refreshToken) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const db = await dbPromise;
    const encryptedAccessToken = encryptToken(accessToken, process.env.SECRET_KEY);
    const encryptedRefreshToken = encryptToken(refreshToken, process.env.SECRET_KEY);

    console.log("Encrypted Access Token:", encryptedAccessToken);
    console.log("Encrypted Refresh Token:", encryptedRefreshToken);
    console.log("Key Access Token:", encryptedAccessToken.key);
    console.log("Key Refresh Token:", encryptedRefreshToken.key);

    let result = await db.run(
      "INSERT INTO tokens (user_email, access_token, refresh_token, iv_access_token, iv_refresh_token, key_access_token, key_refresh_token) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(user_email) DO UPDATE SET access_token=excluded.access_token, refresh_token=excluded.refresh_token",
      [userEmail, encryptedAccessToken.encryptedToken, encryptedRefreshToken.encryptedToken, encryptedAccessToken.iv, encryptedRefreshToken.iv, encryptedAccessToken.key, encryptedRefreshToken.key]
    );

    console.log("Database insertion result:", result);

    res.json({ success: true, message: "Token saved securely" });
  } catch (error) {
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

// Retrieve Dropbox token
app.get("/get-token/:userEmail", async (req, res) => {
  const { userEmail } = req.params;

  try {
    const db = await dbPromise;
    const tokenData = await db.get("SELECT * FROM tokens WHERE user_email = ?", [
      userEmail,
    ]);

    if (!tokenData) {
      return res.status(404).json({ error: "Token not found" });
    }
    console.log("tokenData", tokenData)

    let decryptedAccessToken = decryptToken(tokenData.access_token, tokenData.key_access_token, tokenData.iv_access_token)
    let decryptedRefreshToken = decryptToken(tokenData.refresh_token, tokenData.key_refresh_token, tokenData.iv_refresh_token)

    res.json({accessToken: decryptedAccessToken, refreshToken: decryptedRefreshToken});
  } catch (error) {
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
