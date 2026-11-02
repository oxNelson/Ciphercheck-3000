try {
  process.loadEnvFile();
} catch (_) {}

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Rate limiter for authentication attempts (IP-based)
const loginAttempts = new Map(); // ip -> { count, resetAt }
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_ATTEMPTS = 5;

export function checkRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record || record.resetAt <= now) {
    loginAttempts.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return { allowed: true, remaining: MAX_ATTEMPTS - 1 };
  }
  if (record.count >= MAX_ATTEMPTS) {
    return { allowed: false, remaining: 0, resetInSeconds: Math.ceil((record.resetAt - now) / 1000) };
  }
  record.count += 1;
  return { allowed: true, remaining: MAX_ATTEMPTS - record.count };
}

export function resetRateLimit(ip) {
  loginAttempts.delete(ip);
}

// Secure Password Hashing: uses bcryptjs (matching existing database accounts) or scrypt
export async function hashPassword(password) {
  try {
    const { default: bcrypt } = await import("bcryptjs");
    return await bcrypt.hash(password, 12);
  } catch (_) {
    return new Promise((resolve, reject) => {
      const salt = crypto.randomBytes(16).toString("hex");
      crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) return reject(err);
        resolve(`scrypt:${salt}:${derivedKey.toString("hex")}`);
      });
    });
  }
}

export async function verifyPassword(password, storedHash) {
  if (!storedHash) return false;

  // Support bcrypt hashes ($2a$, $2b$, $2y$)
  if (storedHash.startsWith("$2")) {
    try {
      const { default: bcrypt } = await import("bcryptjs");
      return await bcrypt.compare(password, storedHash);
    } catch (_) {
      return false;
    }
  }

  // Support scrypt hashes
  if (storedHash.startsWith("scrypt:")) {
    return new Promise((resolve) => {
      const [, salt, originalKeyHex] = storedHash.split(":");
      if (!salt || !originalKeyHex) {
        return resolve(false);
      }
      crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) return resolve(false);
        const originalKey = Buffer.from(originalKeyHex, "hex");
        if (originalKey.length !== derivedKey.length) return resolve(false);
        resolve(crypto.timingSafeEqual(originalKey, derivedKey));
      });
    });
  }

  return false;
}

// In-Memory Data Store (used when DATABASE_URL is not set or unavailable)
const memoryUsers = new Map(); // id -> user
const memoryUsersByEmail = new Map(); // lowercase email -> user
const memorySessions = new Map(); // sessionId -> { userId, expiresAt }
const memorySavedReports = new Map(); // id -> reportRecord
const memoryUserRecommendations = new Map(); // userId -> { addressed: string[], dismissed: string[] }

let pgPool = null;
let isPostgresReady = false;
let dbStatus = {
  type: "uninitialized",
  ready: false,
  persistent: false,
  error: null,
};

export function getDatabaseStatus() {
  return {
    ready: dbStatus.ready,
    type: dbStatus.type,
    persistent: dbStatus.persistent,
    isPostgres: isPostgresReady && !!pgPool,
    error: dbStatus.error || null,
  };
}

export function isDatabasePostgres() {
  return isPostgresReady && !!pgPool;
}

export async function closeDatabase() {
  if (pgPool) {
    try {
      await pgPool.end();
    } catch (_) {}
    pgPool = null;
    isPostgresReady = false;
    dbStatus = { type: "closed", ready: false, persistent: false, error: null };
  }
}

export function resetMemoryStore() {
  memoryUsers.clear();
  memoryUsersByEmail.clear();
  memorySessions.clear();
  memorySavedReports.clear();
  memoryUserRecommendations.clear();
}

export function enableInMemoryFallback() {
  if (pgPool) {
    try {
      pgPool.end();
    } catch (_) {}
    pgPool = null;
  }
  isPostgresReady = false;
  dbStatus = { type: "in-memory-fallback", ready: true, persistent: false, error: null };
  return dbStatus;
}

export async function initDatabase() {
  const isProduction = process.env.NODE_ENV === "production";
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    if (isProduction) {
      const errMsg = "[CipherCheck Database] FATAL: DATABASE_URL is not configured in production environment. In-memory storage is not permitted in production.";
      console.error(errMsg);
      dbStatus = { type: "uninitialized", ready: false, persistent: false, error: errMsg };
      throw new Error(errMsg);
    }
    console.log("[CipherCheck Database] NOTICE: DATABASE_URL is not configured in this environment.");
    console.log("[CipherCheck Database] Running with ephemeral in-memory persistence. Data will not persist across server restarts.");
    dbStatus = { type: "in-memory", ready: true, persistent: false, error: null };
    return dbStatus;
  }

  try {
    const pgModule = await import("pg");
    const Pool = pgModule.default?.Pool || pgModule.Pool;
    const poolConfig = {
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5000,
    };
    if (databaseUrl.includes("sslmode=require") || databaseUrl.includes("neon.tech") || databaseUrl.includes("supabase.co")) {
      poolConfig.ssl = { rejectUnauthorized: false };
    }
    pgPool = new Pool(poolConfig);
    pgPool.on("error", (err) => {
      console.error("[CipherCheck Database] Unexpected client error in connection pool:", err.message);
    });

    // Test connection
    const client = await pgPool.connect();
    try {
      // Run migrations in lib/db/migrations
      const migrationsDir = path.join(__dirname, "lib", "db", "migrations");
      if (fs.existsSync(migrationsDir)) {
        const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith(".sql")).sort();
        for (const file of files) {
          const sql = fs.readFileSync(path.join(migrationsDir, file), "utf-8");
          await client.query(sql);
        }
      }
      // Ensure nickname column exists
      await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS nickname VARCHAR(30);");
      // Ensure threat intel columns exist on saved_reports
      await client.query("ALTER TABLE saved_reports ADD COLUMN IF NOT EXISTS threat_intel_status VARCHAR(50) DEFAULT 'unverified';");
      await client.query("ALTER TABLE saved_reports ADD COLUMN IF NOT EXISTS threat_intel_matches INTEGER DEFAULT 0;");
      isPostgresReady = true;
      dbStatus = { type: "postgres", ready: true, persistent: true, error: null };
      console.log("[CipherCheck Database] Successfully connected to PostgreSQL database and applied/verified migrations.");
      return dbStatus;
    } finally {
      client.release();
    }
  } catch (err) {
    if (pgPool) {
      try {
        await pgPool.end();
      } catch (_) {}
      pgPool = null;
    }
    isPostgresReady = false;
    if (isProduction) {
      const errMsg = `[CipherCheck Database] FATAL: Failed to connect to PostgreSQL in production: ${err.message}`;
      console.error(errMsg);
      dbStatus = { type: "postgres-error", ready: false, persistent: false, error: errMsg };
      throw new Error(errMsg);
    }
    console.warn("[CipherCheck Database] Warning: Failed to connect to PostgreSQL:", err.message);
    console.warn("[CipherCheck Database] Falling back to ephemeral in-memory store for session and scan storage.");
    dbStatus = { type: "in-memory-fallback", ready: true, persistent: false, error: err.message };
    return dbStatus;
  }
}

export async function findUserByEmail(email) {
  const normalizedEmail = email.trim().toLowerCase();
  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "SELECT id, email, nickname, password_hash as \"passwordHash\", is_verified as \"isVerified\", created_at as \"createdAt\" FROM users WHERE LOWER(email) = $1 LIMIT 1",
      [normalizedEmail]
    );
    return res.rows[0] || null;
  }
  return memoryUsersByEmail.get(normalizedEmail) || null;
}

export async function findUserById(id) {
  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "SELECT id, email, nickname, is_verified as \"isVerified\", created_at as \"createdAt\" FROM users WHERE id = $1 LIMIT 1",
      [String(id)]
    );
    return res.rows[0] || null;
  }
  const user = memoryUsers.get(String(id));
  if (!user) return null;
  const { passwordHash, ...safeUser } = user;
  return safeUser;
}

export async function createUser(email, passwordHash, nickname = null) {
  const normalizedEmail = email.trim().toLowerCase();
  const now = new Date();
  const id = crypto.randomUUID();
  const cleanNickname =
    typeof nickname === "string" && nickname.trim().length >= 2 && nickname.trim().length <= 30
      ? nickname.trim()
      : null;

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "INSERT INTO users (id, email, password_hash, nickname, is_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id, email, nickname, is_verified as \"isVerified\", created_at as \"createdAt\"",
      [id, normalizedEmail, passwordHash, cleanNickname, false, now]
    );
    return res.rows[0];
  }

  const user = {
    id,
    email: normalizedEmail,
    passwordHash,
    nickname: cleanNickname,
    isVerified: false,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };

  memoryUsers.set(id, user);
  memoryUsersByEmail.set(normalizedEmail, user);
  const { passwordHash: _, ...safeUser } = user;
  return safeUser;
}

export async function updateUserNickname(userId, nickname) {
  if (!userId) return null;
  const cleanNickname = typeof nickname === "string" ? nickname.trim() : "";
  if (cleanNickname.length < 2 || cleanNickname.length > 30) {
    throw new Error("Nickname must be between 2 and 30 characters long.");
  }
  if (/[\r\n\t\0]/.test(cleanNickname) || /<[^>]*>/.test(cleanNickname)) {
    throw new Error("Nickname cannot contain HTML tags or control characters.");
  }

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "UPDATE users SET nickname = $1, updated_at = NOW() WHERE id = $2 RETURNING id, email, nickname, is_verified as \"isVerified\", created_at as \"createdAt\"",
      [cleanNickname, String(userId)]
    );
    return res.rows[0] || null;
  }

  const user = memoryUsers.get(String(userId));
  if (!user) return null;
  user.nickname = cleanNickname;
  user.updatedAt = new Date().toISOString();
  const { passwordHash: _, ...safeUser } = user;
  return safeUser;
}

export async function setVerificationToken(userId, token, expiresAt) {
  if (isPostgresReady && pgPool) {
    await pgPool.query(
      "UPDATE users SET email_verification_token = $1, email_verification_expires = $2 WHERE id = $3",
      [token, expiresAt, String(userId)]
    );
  } else {
    const user = memoryUsers.get(String(userId));
    if (user) {
      user.emailVerificationToken = token;
      user.emailVerificationExpires = expiresAt;
    }
  }
}

export async function verifyEmailToken(token) {
  if (!token) return null;
  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "UPDATE users SET is_verified = true, email_verification_token = NULL, email_verification_expires = NULL WHERE email_verification_token = $1 AND email_verification_expires > NOW() RETURNING id, email, nickname, is_verified as \"isVerified\", created_at as \"createdAt\"",
      [token]
    );
    return res.rows[0] || null;
  }
  for (const user of memoryUsers.values()) {
    if (user.emailVerificationToken === token && new Date(user.emailVerificationExpires) > new Date()) {
      user.isVerified = true;
      user.emailVerificationToken = null;
      user.emailVerificationExpires = null;
      const { passwordHash: _, ...safeUser } = user;
      return safeUser;
    }
  }
  return null;
}

export async function setPasswordResetToken(identifier, token, expiresAt) {
  if (!identifier) return false;
  const str = String(identifier).trim();
  const isEmail = str.includes("@");
  if (isPostgresReady && pgPool) {
    const query = isEmail
      ? "UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE LOWER(email) = LOWER($3) RETURNING id"
      : "UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE id = $3 RETURNING id";
    const res = await pgPool.query(query, [token, expiresAt, str]);
    return Boolean(res.rows.length);
  }
  const user = isEmail
    ? memoryUsersByEmail.get(str.toLowerCase())
    : memoryUsers.get(str);
  if (user) {
    user.passwordResetToken = token;
    user.passwordResetExpires = expiresAt;
    return true;
  }
  return false;
}

export async function resetPasswordWithToken(token, newPasswordHash) {
  if (!token) return null;
  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires = NULL, updated_at = NOW() WHERE password_reset_token = $2 AND password_reset_expires > NOW() RETURNING id, email",
      [newPasswordHash, token]
    );
    if (!res.rows.length) return null;
    const user = res.rows[0];
    await pgPool.query("DELETE FROM sessions WHERE user_id = $1", [user.id]);
    return user;
  }
  for (const user of memoryUsers.values()) {
    if (user.passwordResetToken === token && new Date(user.passwordResetExpires) > new Date()) {
      user.passwordHash = newPasswordHash;
      user.passwordResetToken = null;
      user.passwordResetExpires = null;
      for (const [sId, s] of memorySessions.entries()) {
        if (s.userId === user.id) {
          memorySessions.delete(sId);
        }
      }
      return { id: user.id, email: user.email };
    }
  }
  return null;
}

export async function createSession(userId) {
  const sessionId = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  if (isPostgresReady && pgPool) {
    await pgPool.query(
      "INSERT INTO sessions (id, user_id, created_at, last_active_at, expires_at) VALUES ($1, $2, NOW(), NOW(), $3)",
      [sessionId, String(userId), expiresAt]
    );
  } else {
    memorySessions.set(sessionId, { userId: String(userId), expiresAt });
  }

  return { sessionId, expiresAt };
}

export async function findSession(sessionId) {
  if (!sessionId) return null;

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "SELECT s.id, s.user_id as \"userId\", s.expires_at as \"expiresAt\", u.email, u.nickname, u.is_verified as \"isVerified\", u.created_at as \"createdAt\" FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = $1 AND s.expires_at > NOW() LIMIT 1",
      [sessionId]
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      session: { id: row.id, userId: row.userId, expiresAt: row.expiresAt },
      user: {
        id: row.userId,
        email: row.email,
        nickname: row.nickname || null,
        isVerified: row.isVerified,
        createdAt: row.createdAt,
      },
    };
  }

  const record = memorySessions.get(sessionId);
  if (!record) return null;
  if (new Date(record.expiresAt) <= new Date()) {
    memorySessions.delete(sessionId);
    return null;
  }
  const user = await findUserById(record.userId);
  if (!user) return null;
  return {
    session: { id: sessionId, userId: record.userId, expiresAt: record.expiresAt },
    user,
  };
}

export async function deleteSession(sessionId) {
  if (!sessionId) return;
  if (isPostgresReady && pgPool) {
    await pgPool.query("DELETE FROM sessions WHERE id = $1", [sessionId]);
  } else {
    memorySessions.delete(sessionId);
  }
}

export function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  for (const pair of cookieHeader.split(";")) {
    const [name, ...val] = pair.trim().split("=");
    if (name) {
      cookies[name] = decodeURIComponent(val.join("="));
    }
  }
  return cookies;
}

export function serializeSessionCookie(sessionId, expiresAt, isSecure = false) {
  const maxAge = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
  const secureFlag = isSecure || process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secureFlag}`;
}

export function serializeClearedCookie(isSecure = false) {
  const secureFlag = isSecure || process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `session_id=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureFlag}`;
}

// ============================================================================
// Saved Security Scan Reports Store & Redaction
// ============================================================================

const SENSITIVE_PARAM_KEYS = new Set([
  "token", "auth", "key", "password", "pass", "pwd", "api_key", "apikey",
  "secret", "access_token", "refresh_token", "session", "session_id", "sessionid",
  "code", "sig", "signature", "bearer", "jwt", "credential", "private", "pin"
]);

export function redactSensitiveUrl(rawUrl) {
  if (typeof rawUrl !== "string") return "";
  try {
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawUrl);
    const parsed = new URL(hasScheme ? rawUrl : "http://" + rawUrl);
    // 1. Strip/redact authority credentials
    if (parsed.username || parsed.password) {
      parsed.username = "[REDACTED]";
      parsed.password = "";
    }

    // 2. Redact sensitive query parameters
    const params = new URLSearchParams(parsed.search);
    for (const [key, value] of Array.from(params.entries())) {
      const lowerKey = key.toLowerCase();
      const isSensitiveKey =
        SENSITIVE_PARAM_KEYS.has(lowerKey) ||
        Array.from(SENSITIVE_PARAM_KEYS).some((k) => lowerKey.includes(k));
      const isHighEntropy = value.length >= 24 && /^[a-zA-Z0-9_\-]+$/.test(value);

      if (isSensitiveKey || isHighEntropy) {
        params.set(key, "[REDACTED]");
      }
    }
    let searchStr = params.toString();
    if (searchStr) {
      searchStr = searchStr.replace(/%5BREDACTED%5D/gi, "[REDACTED]");
      parsed.search = "?" + searchStr;
    } else {
      parsed.search = "";
    }
    let res = parsed.toString().replace(/%5BREDACTED%5D/gi, "[REDACTED]");
    if (!hasScheme && res.startsWith("http://")) {
      res = res.slice(7);
    }
    return res;
  } catch (_) {
    return rawUrl.replace(/:[^@]+@/, ":[REDACTED]@");
  }
}

export async function saveReport(userId, analysisData) {
  if (!userId) {
    throw new Error("User ID is required to save a report.");
  }
  if (!analysisData || typeof analysisData !== "object" || !analysisData.urlParts) {
    throw new Error("Valid analysis data is required.");
  }

  const id = crypto.randomUUID();
  const rawUrl = String(analysisData.rawInput || "");
  const redactedUrl = redactSensitiveUrl(rawUrl);
  const hostname = String(analysisData.urlParts.hostname || "");
  const registeredDomain = String(analysisData.urlParts.registeredDomain || hostname);
  const riskLevel = String(analysisData.verdict?.level || "low").toLowerCase();
  const verdictTitle = String(analysisData.verdict?.title || "Security Assessment");
  const verdictSummary = String(analysisData.verdict?.summary || "");
  const findingsCount = Array.isArray(analysisData.findings) ? analysisData.findings.length : 0;
  const createdAt = new Date();

  // Create sanitized analysis data copy with redacted URLs to ensure sensitive data is not kept in jsonb
  const sanitizedAnalysisData = {
    ...analysisData,
    rawInput: redactedUrl,
    normalizedUrl: redactSensitiveUrl(analysisData.normalizedUrl || rawUrl),
    facts: Array.isArray(analysisData.facts)
      ? analysisData.facts.map((f) => {
          if (f.label === "Query Parameters" && f.value && f.value !== "(none)") {
            return { ...f, value: redactSensitiveUrl("http://example.com" + f.value).replace("http://example.com", "") };
          }
          return f;
        })
      : [],
  };

  const threatIntelStatus = String(
    analysisData.threatIntelligence?.summary?.hasConfirmedThreat
      ? "confirmed_threat"
      : analysisData.threatIntelligence?.status || analysisData.verdict?.categoryKey || "unverified"
  );
  const threatIntelMatches = Number(analysisData.threatIntelligence?.summary?.maliciousMatches || 0);

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      `INSERT INTO saved_reports 
        (id, user_id, url, redacted_url, hostname, registered_domain, risk_level, verdict_title, verdict_summary, findings_count, analysis_data, threat_intel_status, threat_intel_matches, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13, $14)
       RETURNING id, user_id as "userId", url, redacted_url as "redactedUrl", hostname, registered_domain as "registeredDomain",
                 risk_level as "riskLevel", verdict_title as "verdictTitle", verdict_summary as "verdictSummary",
                 findings_count as "findingsCount", threat_intel_status as "threatIntelStatus",
                 threat_intel_matches as "threatIntelMatches", analysis_data as "analysisData", created_at as "createdAt"`,
      [
        id,
        String(userId),
        redactedUrl, // Store redactedUrl as URL to protect privacy in DB
        redactedUrl,
        hostname,
        registeredDomain,
        riskLevel,
        verdictTitle,
        verdictSummary,
        findingsCount,
        JSON.stringify(sanitizedAnalysisData),
        threatIntelStatus,
        threatIntelMatches,
        createdAt,
      ]
    );
    const row = res.rows[0];
    if (row && typeof row.analysisData === "string") {
      try {
        row.analysisData = JSON.parse(row.analysisData);
      } catch (_) {}
    }
    return row;
  }

  const record = {
    id,
    userId: String(userId),
    url: redactedUrl,
    redactedUrl,
    hostname,
    registeredDomain,
    riskLevel,
    verdictTitle,
    verdictSummary,
    findingsCount,
    threatIntelStatus,
    threatIntelMatches,
    analysisData: sanitizedAnalysisData,
    createdAt,
  };
  memorySavedReports.set(id, record);
  return record;
}

export async function getSavedReports(userId, options = {}) {
  const uid = String(userId || "");
  const limit = Math.max(1, Math.min(50, Number(options.limit) || 20));
  const offset = Math.max(0, Number(options.offset) || 0);
  const riskFilter = options.riskLevel && options.riskLevel !== "all" ? String(options.riskLevel).toLowerCase() : null;
  const search = options.search && typeof options.search === "string" ? options.search.trim().toLowerCase() : null;

  if (isPostgresReady && pgPool) {
    // 1. Get stats
    const statsRes = await pgPool.query(
      `SELECT 
        COUNT(*)::int as total,
        COUNT(CASE WHEN risk_level = 'clean' THEN 1 END)::int as clean,
        COUNT(CASE WHEN risk_level = 'low' THEN 1 END)::int as low,
        COUNT(CASE WHEN risk_level = 'medium' THEN 1 END)::int as medium,
        COUNT(CASE WHEN risk_level = 'high' THEN 1 END)::int as high
       FROM saved_reports WHERE user_id = $1`,
      [uid]
    );
    const rawStats = statsRes.rows[0] || { total: 0, clean: 0, low: 0, medium: 0, high: 0 };
    const stats = {
      total: Number(rawStats.total || 0),
      clean: Number(rawStats.clean || 0),
      low: Number(rawStats.low || 0),
      medium: Number(rawStats.medium || 0),
      high: Number(rawStats.high || 0),
      byRisk: {
        clean: Number(rawStats.clean || 0),
        low: Number(rawStats.low || 0),
        medium: Number(rawStats.medium || 0),
        high: Number(rawStats.high || 0),
      },
    };

    // 2. Query filtered reports
    const params = [uid];
    const whereClauses = ["user_id = $1"];

    if (riskFilter) {
      params.push(riskFilter);
      whereClauses.push(`risk_level = $${params.length}`);
    }

    if (search) {
      params.push(`%${search}%`);
      const pIdx = params.length;
      whereClauses.push(`(LOWER(hostname) LIKE $${pIdx} OR LOWER(redacted_url) LIKE $${pIdx} OR LOWER(registered_domain) LIKE $${pIdx})`);
    }

    const whereSql = whereClauses.join(" AND ");

    // Total count for current filter
    const countRes = await pgPool.query(`SELECT COUNT(*)::int as count FROM saved_reports WHERE ${whereSql}`, params);
    const totalMatching = countRes.rows[0]?.count || 0;

    // Reports list
    const queryParams = [...params, limit, offset];
    const listRes = await pgPool.query(
      `SELECT id, user_id as "userId", url, redacted_url as "redactedUrl", hostname, registered_domain as "registeredDomain",
              risk_level as "riskLevel", verdict_title as "verdictTitle", verdict_summary as "verdictSummary",
              findings_count as "findingsCount", COALESCE(threat_intel_status, 'unverified') as "threatIntelStatus",
              COALESCE(threat_intel_matches, 0) as "threatIntelMatches", analysis_data as "analysisData", created_at as "createdAt"
       FROM saved_reports
       WHERE ${whereSql}
       ORDER BY created_at DESC
       LIMIT $${queryParams.length - 1} OFFSET $${queryParams.length}`,
      queryParams
    );

    const reports = listRes.rows.map((row) => ({
      ...row,
      analysisData: typeof row.analysisData === "string" ? JSON.parse(row.analysisData) : row.analysisData,
    }));

    return {
      reports,
      total: totalMatching,
      limit,
      offset,
      pagination: {
        total: totalMatching,
        limit,
        offset,
      },
      stats,
    };
  }

  // In-memory fallback
  const userReports = Array.from(memorySavedReports.values()).filter((r) => r.userId === uid);

  const stats = {
    total: userReports.length,
    clean: userReports.filter((r) => r.riskLevel === "clean").length,
    low: userReports.filter((r) => r.riskLevel === "low").length,
    medium: userReports.filter((r) => r.riskLevel === "medium").length,
    high: userReports.filter((r) => r.riskLevel === "high").length,
    byRisk: {
      clean: userReports.filter((r) => r.riskLevel === "clean").length,
      low: userReports.filter((r) => r.riskLevel === "low").length,
      medium: userReports.filter((r) => r.riskLevel === "medium").length,
      high: userReports.filter((r) => r.riskLevel === "high").length,
    },
  };

  let filtered = userReports;
  if (riskFilter) {
    filtered = filtered.filter((r) => r.riskLevel === riskFilter);
  }
  if (search) {
    filtered = filtered.filter(
      (r) =>
        r.hostname.toLowerCase().includes(search) ||
        r.redactedUrl.toLowerCase().includes(search) ||
        r.registeredDomain.toLowerCase().includes(search)
    );
  }

  filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const pageReports = filtered.slice(offset, offset + limit);

  return {
    reports: pageReports,
    total: filtered.length,
    limit,
    offset,
    pagination: {
      total: filtered.length,
      limit,
      offset,
    },
    stats,
  };
}

export async function getSavedReportById(reportId, userId) {
  if (!reportId || !userId) return null;
  const uid = String(userId);

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      `SELECT id, user_id as "userId", url, redacted_url as "redactedUrl", hostname, registered_domain as "registeredDomain",
              risk_level as "riskLevel", verdict_title as "verdictTitle", verdict_summary as "verdictSummary",
              findings_count as "findingsCount", COALESCE(threat_intel_status, 'unverified') as "threatIntelStatus",
              COALESCE(threat_intel_matches, 0) as "threatIntelMatches", analysis_data as "analysisData", created_at as "createdAt"
       FROM saved_reports
       WHERE id = $1 AND user_id = $2
       LIMIT 1`,
      [String(reportId), uid]
    );
    const row = res.rows[0];
    if (!row) return null;
    return {
      ...row,
      analysisData: typeof row.analysisData === "string" ? JSON.parse(row.analysisData) : row.analysisData,
    };
  }

  const record = memorySavedReports.get(String(reportId));
  if (!record || record.userId !== uid) return null;
  return record;
}

export async function deleteSavedReport(reportId, userId) {
  if (!reportId || !userId) return false;
  const uid = String(userId);

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query("DELETE FROM saved_reports WHERE id = $1 AND user_id = $2", [String(reportId), uid]);
    return res.rowCount > 0;
  }

  const record = memorySavedReports.get(String(reportId));
  if (!record || record.userId !== uid) return false;
  memorySavedReports.delete(String(reportId));
  return true;
}

export async function clearAllSavedReports(userId) {
  if (!userId) return 0;
  const uid = String(userId);

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query("DELETE FROM saved_reports WHERE user_id = $1", [uid]);
    return res.rowCount || 0;
  }

  let count = 0;
  for (const [id, record] of Array.from(memorySavedReports.entries())) {
    if (record.userId === uid) {
      memorySavedReports.delete(id);
      count++;
    }
  }
  return count;
}

// ============================================================================
// User Recommendation Preferences & Addressed / Dismissed State
// ============================================================================

export async function getUserRecommendationStatus(userId) {
  if (!userId) return { addressed: [], dismissed: [] };
  const uid = String(userId);

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      `SELECT addressed_ids as "addressedIds", dismissed_ids as "dismissedIds"
       FROM user_recommendations WHERE user_id = $1 LIMIT 1`,
      [uid]
    );
    if (res.rows.length === 0) {
      return { addressed: [], dismissed: [] };
    }
    const row = res.rows[0];
    const parseIds = (raw) => {
      if (Array.isArray(raw)) return raw;
      if (typeof raw === "string") {
        try {
          const parsed = JSON.parse(raw);
          return Array.isArray(parsed) ? parsed : [];
        } catch (_) {}
      }
      return [];
    };
    return {
      addressed: parseIds(row.addressedIds),
      dismissed: parseIds(row.dismissedIds),
    };
  }

  const rec = memoryUserRecommendations.get(uid);
  return {
    addressed: rec ? [...rec.addressed] : [],
    dismissed: rec ? [...rec.dismissed] : [],
  };
}

export async function saveUserRecommendationStatus(userId, { addressed = [], dismissed = [] }) {
  if (!userId) throw new Error("User ID is required to save recommendation status.");
  const uid = String(userId);
  const cleanAddressed = Array.isArray(addressed) ? Array.from(new Set(addressed.map(String))) : [];
  const cleanDismissed = Array.isArray(dismissed) ? Array.from(new Set(dismissed.map(String))) : [];

  if (isPostgresReady && pgPool) {
    await pgPool.query(
      `INSERT INTO user_recommendations (user_id, addressed_ids, dismissed_ids, updated_at)
       VALUES ($1, $2::jsonb, $3::jsonb, NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         addressed_ids = EXCLUDED.addressed_ids,
         dismissed_ids = EXCLUDED.dismissed_ids,
         updated_at = NOW()`,
      [uid, JSON.stringify(cleanAddressed), JSON.stringify(cleanDismissed)]
    );
    return { addressed: cleanAddressed, dismissed: cleanDismissed };
  }

  memoryUserRecommendations.set(uid, {
    addressed: cleanAddressed,
    dismissed: cleanDismissed,
  });
  return { addressed: cleanAddressed, dismissed: cleanDismissed };
}

export async function updateUserRecommendationAction(userId, action, recommendationId) {
  if (!userId) throw new Error("User ID is required.");
  if (!recommendationId && action !== "reset" && action !== "restore") {
    throw new Error("Recommendation ID is required.");
  }
  const current = await getUserRecommendationStatus(userId);
  const recId = String(recommendationId || "");
  let addressed = new Set(current.addressed);
  let dismissed = new Set(current.dismissed);

  switch (action) {
    case "address":
      addressed.add(recId);
      dismissed.delete(recId);
      break;
    case "unaddress":
      addressed.delete(recId);
      break;
    case "dismiss":
      dismissed.add(recId);
      addressed.delete(recId);
      break;
    case "undismiss":
      dismissed.delete(recId);
      break;
    case "restore":
    case "reset":
      addressed.clear();
      dismissed.clear();
      break;
    default:
      throw new Error(`Invalid recommendation action: ${action}`);
  }

  return await saveUserRecommendationStatus(userId, {
    addressed: Array.from(addressed),
    dismissed: Array.from(dismissed),
  });
}

