const express = require("express");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

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
      user_email TEXT,
      access_token TEXT,
      refresh_token TEXT
    )
  `);
}
initDB();

// Hash function for security (optional)
async function hashToken(token) {
  const saltRounds = 10;
  return await bcrypt.hash(token, saltRounds);
}

// Store Dropbox token
app.post("/save-token", async (req, res) => {
  const { userEmail, accessToken, refreshToken } = req.body;

  if (!userEmail || !accessToken || !refreshToken) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const db = await dbPromise;
    const hashedAccessToken = await hashToken(accessToken);
    const hashedRefreshToken = await hashToken(refreshToken);

    await db.run(
      "INSERT INTO tokens user_email, access_token, refresh_token) VALUES (?, ?, ?) ON CONFLICT(user_email) DO UPDATE SET access_token=excluded.access_token, refresh_token=excluded.refresh_token",
      [userEmail, hashedAccessToken, hashedRefreshToken]
    );

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

    res.json(tokenData);
  } catch (error) {
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
