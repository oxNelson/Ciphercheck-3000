try {
  process.loadEnvFile();
} catch (_) {}

import fs from "fs";
import path from "path";
import http from "http";
import crypto from "crypto";
import { fileURLToPath } from "url";
import {
  initDatabase,
  checkRateLimit,
  resetRateLimit,
  hashPassword,
  verifyPassword,
  findUserByEmail,
  createUser,
  updateUserNickname,
  createSession,
  findSession,
  deleteSession,
  parseCookies,
  serializeSessionCookie,
  serializeClearedCookie,
  setVerificationToken,
  verifyEmailToken,
  setPasswordResetToken,
  resetPasswordWithToken,
  saveReport,
  getSavedReports,
  getSavedReportById,
  deleteSavedReport,
  clearAllSavedReports,
  redactSensitiveUrl,
  getUserRecommendationStatus,
  saveUserRecommendationStatus,
  updateUserRecommendationAction,
} from "./server-auth.js";
import {
  isSmtpConfigured,
  sendVerificationEmail,
  sendPasswordResetEmail,
  getBaseUrl,
  isOriginAllowed,
} from "./server-smtp.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;
const HOST = "0.0.0.0";
const staticDir = path.join(__dirname, "ciphercheck");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
};

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function getSessionId(req) {
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.session_id) return cookies.session_id;
  const auth = req.headers.authorization;
  if (auth && auth.startsWith("Bearer ")) {
    return auth.slice(7).trim();
  }
  return null;
}


async function startServer() {
  await initDatabase();

  let expressApp = null;
  try {
    const { default: express } = await import("express");
    const app = express();

    app.set("trust proxy", true);
    app.use(express.json());

    // CORS & Iframe preview header support
    app.use((req, res, next) => {
      const origin = req.headers.origin;
      if (origin && isOriginAllowed(origin, req)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Access-Control-Allow-Credentials", "true");
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
      }
      if (req.method === "OPTIONS") {
        return res.sendStatus(204);
      }
      next();
    });

    const checkIsSecure = (req) =>
      Boolean(req.secure || req.headers["x-forwarded-proto"] === "https" || process.env.NODE_ENV === "production");

    // CSRF defense on state-changing authentication, reports, and recommendations routes
    app.use(["/api/auth", "/api/reports", "/api/recommendations"], (req, res, next) => {
      if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
        return next();
      }
      const origin = req.headers.origin;
      if (origin && !isOriginAllowed(origin, req)) {
        return res.status(403).json({ error: "Invalid request origin." });
      }
      next();
    });

    // Health check
    app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

    // Auth status (SMTP configuration & DB connectivity check)
    app.get("/api/auth/status", (_req, res) => {
      return res.json({
        smtpConfigured: isSmtpConfigured(),
        databaseConnected: true,
      });
    });

    // Auth: Register
    app.post("/api/auth/register", async (req, res) => {
      const isSecure = checkIsSecure(req);
      const { email, password, nickname } = req.body || {};
      if (!isValidEmail(email)) {
        return res.status(400).json({ error: "Please enter a valid email address." });
      }
      if (typeof password !== "string" || password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters long." });
      }

      let sanitizedNickname = null;
      if (nickname !== undefined && nickname !== null && typeof nickname === "string") {
        const trimmed = nickname.trim();
        if (trimmed.length > 0) {
          if (trimmed.length < 2 || trimmed.length > 30) {
            return res.status(400).json({ error: "Nickname must be between 2 and 30 characters long." });
          }
          if (/[\r\n\t\0]/.test(trimmed) || /<[^>]*>/.test(trimmed)) {
            return res.status(400).json({ error: "Nickname cannot contain HTML tags or control characters." });
          }
          sanitizedNickname = trimmed;
        }
      }

      const existing = await findUserByEmail(email);
      if (existing) {
        return res.status(409).json({ error: "An account with this email already exists." });
      }

      try {
        const passwordHash = await hashPassword(password);
        const user = await createUser(email, passwordHash, sanitizedNickname);
        const { sessionId, expiresAt } = await createSession(user.id);

        let emailSent = false;
        if (isSmtpConfigured()) {
          try {
            const verificationToken = crypto.randomBytes(32).toString("hex");
            const tokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
            await setVerificationToken(user.id, verificationToken, tokenExpires);
            await sendVerificationEmail(user.email, verificationToken, getBaseUrl(req));
            emailSent = true;
          } catch (mailErr) {
            console.warn("[Auth] Verification email delivery notice:", mailErr.message);
          }
        }

        res.setHeader("Set-Cookie", serializeSessionCookie(sessionId, expiresAt, isSecure));
        return res.status(201).json({ user, token: sessionId, emailSent });
      } catch (err) {
        console.error("[Auth] Registration error:", err);
        return res.status(500).json({ error: "An unexpected error occurred during registration." });
      }
    });

    // Auth: Login
    app.post("/api/auth/login", async (req, res) => {
      const isSecure = checkIsSecure(req);
      const clientIp = req.ip || req.socket.remoteAddress || "127.0.0.1";
      const rate = checkRateLimit(clientIp);
      if (!rate.allowed) {
        return res.status(429).json({
          error: `Too many login attempts. Please wait ${rate.resetInSeconds} seconds before trying again.`,
        });
      }

      const { email, password } = req.body || {};
      if (!isValidEmail(email) || typeof password !== "string") {
        return res.status(400).json({ error: "Please provide a valid email and password." });
      }

      const user = await findUserByEmail(email);
      if (!user) {
        return res.status(401).json({ error: "Invalid email or password." });
      }

      const isMatch = await verifyPassword(password, user.passwordHash);
      if (!isMatch) {
        return res.status(401).json({ error: "Invalid email or password." });
      }

      resetRateLimit(clientIp);

      // Defense against session fixation: invalidate old session
      const existingSessionId = getSessionId(req);
      if (existingSessionId) {
        await deleteSession(existingSessionId);
      }

      const { sessionId, expiresAt } = await createSession(user.id);
      res.setHeader("Set-Cookie", serializeSessionCookie(sessionId, expiresAt, isSecure));

      return res.json({
        user: {
          id: user.id,
          email: user.email,
          nickname: user.nickname || null,
          isVerified: user.isVerified,
          createdAt: user.createdAt,
        },
        token: sessionId,
      });
    });

    // Auth: Update Nickname
    const handleUpdateNickname = async (req, res) => {
      const sessionId = getSessionId(req);
      if (!sessionId) {
        return res.status(401).json({ error: "Authentication required to update nickname." });
      }

      const sessionData = await findSession(sessionId);
      if (!sessionData || !sessionData.user) {
        return res.status(401).json({ error: "Session expired or invalid. Please sign in again." });
      }

      const { nickname } = req.body || {};
      if (typeof nickname !== "string") {
        return res.status(400).json({ error: "Nickname must be a valid text string." });
      }

      const trimmed = nickname.trim();
      if (trimmed.length < 2 || trimmed.length > 30) {
        return res.status(400).json({ error: "Nickname must be between 2 and 30 characters long." });
      }

      if (/[\r\n\t\0]/.test(trimmed) || /<[^>]*>/.test(trimmed)) {
        return res.status(400).json({ error: "Nickname cannot contain HTML tags or control characters." });
      }

      try {
        const updatedUser = await updateUserNickname(sessionData.user.id, trimmed);
        if (!updatedUser) {
          return res.status(404).json({ error: "User account not found." });
        }
        return res.json({
          success: true,
          message: "Nickname updated successfully.",
          user: {
            id: updatedUser.id,
            email: updatedUser.email,
            nickname: updatedUser.nickname,
            isVerified: updatedUser.isVerified,
            createdAt: updatedUser.createdAt,
          },
        });
      } catch (err) {
        console.error("[Auth] Nickname update error:", err);
        return res.status(400).json({ error: err.message || "Failed to update nickname." });
      }
    };

    app.put("/api/auth/nickname", handleUpdateNickname);
    app.post("/api/auth/nickname", handleUpdateNickname);
    app.patch("/api/auth/nickname", handleUpdateNickname);

    // Auth: Logout
    app.post("/api/auth/logout", async (req, res) => {
      const isSecure = checkIsSecure(req);
      const sessionId = getSessionId(req);
      if (sessionId) {
        await deleteSession(sessionId);
      }
      res.setHeader("Set-Cookie", serializeClearedCookie(isSecure));
      return res.json({ success: true });
    });

    // Auth: Current Session (Me)
    app.get("/api/auth/me", async (req, res) => {
      const isSecure = checkIsSecure(req);
      const sessionId = getSessionId(req);
      if (!sessionId) {
        return res.json({ user: null });
      }
      const sessionData = await findSession(sessionId);
      if (!sessionData) {
        res.setHeader("Set-Cookie", serializeClearedCookie(isSecure));
        return res.json({ user: null });
      }
      return res.json({ user: sessionData.user });
    });

    // Auth: Email Verification (handles both token link and manual input)
    app.post("/api/auth/verify-email", async (req, res) => {
      if (!isSmtpConfigured()) {
        return res.status(503).json({
          error: "SMTP email delivery service is not configured. Email verification is currently unavailable in this environment.",
        });
      }

      const token = req.body?.token || req.query?.token;
      if (!token || typeof token !== "string") {
        return res.status(400).json({ error: "Verification token is required." });
      }

      const verifiedUser = await verifyEmailToken(token.trim());
      if (!verifiedUser) {
        return res.status(400).json({ error: "Verification link is invalid or has expired." });
      }

      const isSecure = checkIsSecure(req);
      const { sessionId, expiresAt } = await createSession(verifiedUser.id);
      res.setHeader("Set-Cookie", serializeSessionCookie(sessionId, expiresAt, isSecure));

      return res.json({
        success: true,
        message: "Your email has been verified successfully!",
        user: verifiedUser,
        token: sessionId,
      });
    });

    // Auth: Resend Verification Email
    app.post("/api/auth/resend-verification", async (req, res) => {
      if (!isSmtpConfigured()) {
        return res.status(503).json({
          error: "SMTP email delivery service is not configured.",
        });
      }

      const sessionId = getSessionId(req);
      if (!sessionId) {
        return res.status(401).json({ error: "Please sign in to resend verification." });
      }

      const sessionData = await findSession(sessionId);
      if (!sessionData) {
        return res.status(401).json({ error: "Session expired." });
      }

      if (sessionData.user.isVerified) {
        return res.json({ success: true, message: "Your email is already verified." });
      }

      try {
        const token = crypto.randomBytes(32).toString("hex");
        const tokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await setVerificationToken(sessionData.user.id, token, tokenExpires);
        await sendVerificationEmail(sessionData.user.email, token, getBaseUrl(req));
        return res.json({ success: true, message: "Verification email has been sent." });
      } catch (err) {
        console.error("[Auth] Resend verification error:", err);
        return res.status(500).json({ error: "Failed to send verification email. Please check SMTP configuration." });
      }
    });

    // Auth: Forgot Password Request
    app.post("/api/auth/forgot-password", async (req, res) => {
      if (!isSmtpConfigured()) {
        return res.status(503).json({
          error: "SMTP email delivery service is not configured. Password recovery is unavailable in this environment.",
        });
      }

      const { email } = req.body || {};
      if (!isValidEmail(email)) {
        return res.status(400).json({ error: "Please enter a valid email address." });
      }

      try {
        const token = crypto.randomBytes(32).toString("hex");
        const tokenExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
        const userExists = await setPasswordResetToken(email, token, tokenExpires);

        if (userExists) {
          await sendPasswordResetEmail(email.trim().toLowerCase(), token, getBaseUrl(req));
        }

        // Always return success to prevent email enumeration
        return res.json({
          success: true,
          message: "If an account exists with this email address, a password reset link has been sent.",
        });
      } catch (err) {
        console.error("[Auth] Forgot password error:", err);
        return res.status(500).json({ error: "Failed to process password reset request." });
      }
    });

    // Auth: Reset Password Submission
    app.post("/api/auth/reset-password", async (req, res) => {
      if (!isSmtpConfigured()) {
        return res.status(503).json({
          error: "SMTP email delivery service is not configured.",
        });
      }

      const { token, newPassword, password } = req.body || {};
      const targetPassword = typeof newPassword === "string" ? newPassword : password;
      if (!token || typeof token !== "string") {
        return res.status(400).json({ error: "Password reset token is required." });
      }
      if (typeof targetPassword !== "string" || targetPassword.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters long." });
      }

      try {
        const newPasswordHash = await hashPassword(targetPassword);
        const user = await resetPasswordWithToken(token.trim(), newPasswordHash);
        if (!user) {
          return res.status(400).json({ error: "Password reset token is invalid or has expired." });
        }
        return res.json({
          success: true,
          message: "Your password has been reset successfully. You can now sign in with your new password.",
        });
      } catch (err) {
        console.error("[Auth] Reset password error:", err);
        return res.status(500).json({ error: "Failed to reset password." });
      }
    });

    // =========================================================================
    // Security Dashboard & Saved Scan Reports Endpoints
    // =========================================================================

    // Reports: Save a new analysis report (authenticated user only)
    app.post("/api/reports", async (req, res) => {
      const sessionId = getSessionId(req);
      if (!sessionId) {
        return res.status(401).json({ error: "Please sign in to save security scan reports." });
      }

      const sessionData = await findSession(sessionId);
      if (!sessionData) {
        return res.status(401).json({ error: "Your session has expired. Please sign in again." });
      }

      const { analysis } = req.body || {};
      if (!analysis || typeof analysis !== "object" || !analysis.isValid || !analysis.urlParts) {
        return res.status(400).json({ error: "A valid URL analysis object is required to save a report." });
      }

      try {
        const saved = await saveReport(sessionData.user.id, analysis);
        return res.status(201).json({
          success: true,
          message: "Security analysis report saved to your private dashboard.",
          report: saved,
        });
      } catch (err) {
        console.error("[Reports] Save report error:", err);
        return res.status(500).json({ error: err.message || "Failed to save security report." });
      }
    });

    // Reports: Get user's saved reports list, pagination, and dashboard stats
    app.get("/api/reports", async (req, res) => {
      const sessionId = getSessionId(req);
      if (!sessionId) {
        return res.status(401).json({ error: "Please sign in to access your security scan history." });
      }

      const sessionData = await findSession(sessionId);
      if (!sessionData) {
        return res.status(401).json({ error: "Your session has expired. Please sign in again." });
      }

      try {
        const { limit, offset, risk, search } = req.query;
        const result = await getSavedReports(sessionData.user.id, {
          limit,
          offset,
          riskLevel: risk,
          search,
        });

        return res.json({
          success: true,
          ...result,
        });
      } catch (err) {
        console.error("[Reports] List reports error:", err);
        return res.status(500).json({ error: "Failed to retrieve security reports." });
      }
    });

    // Reports: Get single report details by ID
    app.get("/api/reports/:id", async (req, res) => {
      const sessionId = getSessionId(req);
      if (!sessionId) {
        return res.status(401).json({ error: "Please sign in to view security reports." });
      }

      const sessionData = await findSession(sessionId);
      if (!sessionData) {
        return res.status(401).json({ error: "Your session has expired. Please sign in again." });
      }

      try {
        const report = await getSavedReportById(req.params.id, sessionData.user.id);
        if (!report) {
          return res.status(404).json({ error: "Security report not found." });
        }

        return res.json({
          success: true,
          report,
        });
      } catch (err) {
        console.error("[Reports] Get report error:", err);
        return res.status(500).json({ error: "Failed to retrieve security report." });
      }
    });

    // Reports: Delete a single report by ID
    app.delete("/api/reports/:id", async (req, res) => {
      const sessionId = getSessionId(req);
      if (!sessionId) {
        return res.status(401).json({ error: "Please sign in to manage security reports." });
      }

      const sessionData = await findSession(sessionId);
      if (!sessionData) {
        return res.status(401).json({ error: "Your session has expired. Please sign in again." });
      }

      try {
        const deleted = await deleteSavedReport(req.params.id, sessionData.user.id);
        if (!deleted) {
          return res.status(404).json({ error: "Security report not found or already deleted." });
        }

        return res.json({
          success: true,
          message: "Security report deleted successfully.",
        });
      } catch (err) {
        console.error("[Reports] Delete report error:", err);
        return res.status(500).json({ error: "Failed to delete security report." });
      }
    });

    // Reports: Clear all saved reports for the authenticated user
    app.delete("/api/reports", async (req, res) => {
      const sessionId = getSessionId(req);
      if (!sessionId) {
        return res.status(401).json({ error: "Please sign in to manage security reports." });
      }

      const sessionData = await findSession(sessionId);
      if (!sessionData) {
        return res.status(401).json({ error: "Your session has expired. Please sign in again." });
      }

      try {
        const count = await clearAllSavedReports(sessionData.user.id);
        return res.json({
          success: true,
          message: "All saved security scan reports have been deleted.",
          deletedCount: count,
        });
      } catch (err) {
        console.error("[Reports] Clear reports error:", err);
        return res.status(500).json({ error: "Failed to clear security reports." });
      }
    });

    // =========================================================================
    // Personal Security Center: Recommendation Status Endpoints
    // =========================================================================

    // Recommendations: Get addressed and dismissed status for authenticated user
    app.get("/api/recommendations/status", async (req, res) => {
      const sessionId = getSessionId(req);
      if (!sessionId) {
        return res.status(401).json({ error: "Authentication required to retrieve recommendation preferences." });
      }

      const sessionData = await findSession(sessionId);
      if (!sessionData) {
        return res.status(401).json({ error: "Session expired or invalid." });
      }

      try {
        const status = await getUserRecommendationStatus(sessionData.user.id);
        return res.json({
          success: true,
          ...status,
        });
      } catch (err) {
        console.error("[Recommendations] Get status error:", err);
        return res.status(500).json({ error: "Failed to load recommendation status." });
      }
    });

    // Recommendations: Update addressed and dismissed status for authenticated user
    app.post("/api/recommendations/status", async (req, res) => {
      const sessionId = getSessionId(req);
      if (!sessionId) {
        return res.status(401).json({ error: "Authentication required to update recommendation preferences." });
      }

      const sessionData = await findSession(sessionId);
      if (!sessionData) {
        return res.status(401).json({ error: "Session expired or invalid." });
      }

      const { action, id, addressed, dismissed } = req.body || {};

      try {
        if (action) {
          const updated = await updateUserRecommendationAction(sessionData.user.id, action, id);
          return res.json({
            success: true,
            message: `Recommendation ${action} updated.`,
            ...updated,
          });
        }

        if (Array.isArray(addressed) || Array.isArray(dismissed)) {
          const updated = await saveUserRecommendationStatus(sessionData.user.id, {
            addressed: addressed || [],
            dismissed: dismissed || [],
          });
          return res.json({
            success: true,
            message: "Recommendation preferences saved.",
            ...updated,
          });
        }

        return res.status(400).json({ error: "Action or status lists (addressed/dismissed) required." });
      } catch (err) {
        console.error("[Recommendations] Save status error:", err);
        return res.status(400).json({ error: err.message || "Failed to update recommendation status." });
      }
    });

    // Serve static files
    app.use(express.static(staticDir));
    app.use("/ciphercheck", express.static(staticDir));
    app.get("*", (_req, res) => res.sendFile(path.join(staticDir, "index.html")));

    expressApp = app;
  } catch (err) {
    console.warn("Express not loaded, using built-in http server:", err.message);
  }

  if (expressApp) {
    expressApp.listen(PORT, HOST, () => {
      console.log(`CipherCheck Express server running at http://${HOST}:${PORT}`);
    });
  } else {
    const server = http.createServer((req, res) => {
      if (req.url === "/api/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ status: "ok" }));
      }

      let filePath = req.url ? req.url.split("?")[0] : "/";
      if (filePath.startsWith("/ciphercheck")) {
        filePath = filePath.replace(/^\/ciphercheck/, "") || "/";
      }
      if (filePath === "/") {
        filePath = "/index.html";
      }

      let resolvedPath = path.join(staticDir, filePath);
      if (!fs.existsSync(resolvedPath) || fs.statSync(resolvedPath).isDirectory()) {
        resolvedPath = path.join(staticDir, "index.html");
      }

      const ext = path.extname(resolvedPath).toLowerCase();
      const contentType = MIME_TYPES[ext] || "application/octet-stream";

      fs.readFile(resolvedPath, (err, data) => {
        if (err) {
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end("Server Error");
        } else {
          res.writeHead(200, { "Content-Type": contentType });
          res.end(data);
        }
      });
    });

    server.listen(PORT, HOST, () => {
      console.log(`CipherCheck built-in HTTP server running at http://${HOST}:${PORT}`);
    });
  }
}

startServer();
