import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import {
  isSmtpConfigured,
  getSmtpStatus,
  getSmtpTransporter,
  setCustomTransporter,
  resetSmtpTransporter,
  verifySmtpConnection,
  sendVerificationEmail,
  sendPasswordResetEmail,
  getBaseUrl,
  transformAppHost,
  sanitizeAppUrl,
} from "../server-smtp.js";
import {
  createUser,
  findUserByEmail,
  findUserById,
  hashPassword,
  verifyPassword,
  createSession,
  findSession,
  setVerificationToken,
  verifyEmailToken,
  setPasswordResetToken,
  resetPasswordWithToken,
  checkRateLimit,
  resetRateLimit,
} from "../server-auth.js";

describe("SMTP Integration & End-to-End Email Verification", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    resetSmtpTransporter();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    resetSmtpTransporter();
  });

  describe("1. Configuration & Truthful Reporting", () => {
    test("Reports unconfigured with missing variables when SMTP environment variables are absent", () => {
      delete process.env.SMTP_HOST;
      delete process.env.SMTP_USER;
      delete process.env.SMTP_PASS;

      assert.equal(isSmtpConfigured(), false);
      const status = getSmtpStatus();
      assert.equal(status.configured, false);
      assert.deepEqual(status.missingVariables.sort(), ["SMTP_HOST", "SMTP_PASS", "SMTP_USER"]);
      assert.ok(status.requiredVariables.includes("SMTP_HOST"));
      assert.ok(status.requiredVariables.includes("SMTP_USER"));
      assert.ok(status.requiredVariables.includes("SMTP_PASS"));
    });

    test("Reports exact missing variable when partial SMTP variables are provided", () => {
      process.env.SMTP_HOST = "smtp.mailgun.org";
      process.env.SMTP_USER = "postmaster@ciphercheck.org";
      delete process.env.SMTP_PASS;

      assert.equal(isSmtpConfigured(), false);
      const status = getSmtpStatus();
      assert.equal(status.configured, false);
      assert.deepEqual(status.missingVariables, ["SMTP_PASS"]);
    });

    test("Reports configured when all required SMTP variables are present", () => {
      process.env.SMTP_HOST = "smtp.sendgrid.net";
      process.env.SMTP_USER = "apikey";
      process.env.SMTP_PASS = "SG.secret-key-12345";

      assert.equal(isSmtpConfigured(), true);
      const status = getSmtpStatus();
      assert.equal(status.configured, true);
      assert.deepEqual(status.missingVariables, []);
    });

    test("Transporter respects custom port and secure flag for SSL (port 465)", () => {
      process.env.SMTP_HOST = "smtp.example.com";
      process.env.SMTP_USER = "mailer@example.com";
      process.env.SMTP_PASS = "sample-secret";
      process.env.SMTP_PORT = "465";

      const transporter = getSmtpTransporter();
      assert.ok(transporter);
      assert.equal(transporter.options.port, 465);
      assert.equal(transporter.options.secure, true);
    });

    test("Transporter uses port 587 and secure: false for standard TLS", () => {
      process.env.SMTP_HOST = "smtp.example.com";
      process.env.SMTP_USER = "mailer@example.com";
      process.env.SMTP_PASS = "sample-secret";
      process.env.SMTP_PORT = "587";

      const transporter = getSmtpTransporter();
      assert.ok(transporter);
      assert.equal(transporter.options.port, 587);
      assert.equal(transporter.options.secure, false);
    });

    test("verifySmtpConnection returns clear error with missing variables when unconfigured", async () => {
      delete process.env.SMTP_HOST;
      delete process.env.SMTP_USER;
      delete process.env.SMTP_PASS;

      const res = await verifySmtpConnection();
      assert.equal(res.ok, false);
      assert.ok(res.error.includes("SMTP_HOST"));
      assert.ok(res.error.includes("SMTP_USER"));
      assert.ok(res.error.includes("SMTP_PASS"));
    });
  });

  describe("2. End-to-End Registration & Email Verification Flow", () => {
    test("Verification email generation creates expected headers, links, and tokens", async () => {
      process.env.SMTP_HOST = "smtp.example.com";
      process.env.SMTP_USER = "notifications@ciphercheck.org";
      process.env.SMTP_PASS = "super-secret-smtp-pass";
      process.env.SMTP_FROM = "security@ciphercheck.org";

      const sentMails = [];
      const mockTransporter = {
        sendMail: async (mailOptions) => {
          sentMails.push(mailOptions);
          return { messageId: "mock-msg-" + Date.now() };
        },
        verify: async () => true,
      };
      setCustomTransporter(mockTransporter);

      const recipient = "newuser@example.com";
      const token = crypto.randomBytes(32).toString("hex");
      const appUrl = "https://app.ciphercheck.org";

      const result = await sendVerificationEmail(recipient, token, appUrl);
      assert.ok(result.messageId);
      assert.equal(sentMails.length, 1);

      const mail = sentMails[0];
      assert.equal(mail.to, recipient);
      assert.ok(mail.from.includes("security@ciphercheck.org"));
      assert.equal(mail.subject, "Verify your CipherCheck account email");
      assert.ok(mail.text.includes(token));
      assert.ok(mail.text.includes(`https://app.ciphercheck.org/?verifyToken=${token}`));
      assert.ok(mail.html.includes(token));
      assert.ok(mail.html.includes(`https://app.ciphercheck.org/?verifyToken=${token}`));
    });

    test("Account creation, token assignment, and successful verification lifecycle", async () => {
      const email = `flow-verify-${Date.now()}@example.com`;
      const hash = await hashPassword("ValidPassword123!");
      const user = await createUser(email, hash);

      assert.equal(user.isVerified, false);

      // Generate verification token (24-hour expiration)
      const token = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await setVerificationToken(user.id, token, expiresAt);

      // Verify email with valid token
      const verified = await verifyEmailToken(token);
      assert.ok(verified);
      assert.equal(verified.id, user.id);
      assert.equal(verified.isVerified, true);

      // Token is invalidated upon use (replay prevention)
      const secondAttempt = await verifyEmailToken(token);
      assert.equal(secondAttempt, null);

      // Verify in DB that user status is true
      const updatedUser = await findUserById(user.id);
      assert.equal(updatedUser.isVerified, true);
    });

    test("Invalid verification token is rejected", async () => {
      const result = await verifyEmailToken("invalid-tampered-token-12345");
      assert.equal(result, null);
    });

    test("Expired verification token is strictly rejected", async () => {
      const email = `expired-verify-${Date.now()}@example.com`;
      const hash = await hashPassword("ValidPassword123!");
      const user = await createUser(email, hash);

      const token = crypto.randomBytes(32).toString("hex");
      // Expired 10 minutes ago
      const pastExpires = new Date(Date.now() - 10 * 60 * 1000);
      await setVerificationToken(user.id, token, pastExpires);

      const verified = await verifyEmailToken(token);
      assert.equal(verified, null);

      const checkUser = await findUserById(user.id);
      assert.equal(checkUser.isVerified, false);
    });
  });

  describe("3. End-to-End Password Recovery Flow", () => {
    test("Password reset email generation creates expected headers, links, and 1-hour expiration", async () => {
      process.env.SMTP_HOST = "smtp.example.com";
      process.env.SMTP_USER = "auth@ciphercheck.org";
      process.env.SMTP_PASS = "sample-secret";

      const sentMails = [];
      const mockTransporter = {
        sendMail: async (mailOptions) => {
          sentMails.push(mailOptions);
          return { messageId: "reset-msg-" + Date.now() };
        },
      };
      setCustomTransporter(mockTransporter);

      const recipient = "target-user@example.com";
      const token = crypto.randomBytes(32).toString("hex");
      const appUrl = "https://app.ciphercheck.org";

      const result = await sendPasswordResetEmail(recipient, token, appUrl);
      assert.ok(result.messageId);
      assert.equal(sentMails.length, 1);

      const mail = sentMails[0];
      assert.equal(mail.to, recipient);
      assert.equal(mail.subject, "Reset your CipherCheck password");
      assert.ok(mail.text.includes(token));
      assert.ok(mail.text.includes(`https://app.ciphercheck.org/?resetToken=${token}`));
      assert.ok(mail.text.includes("expire in 1 hour"));
      assert.ok(mail.html.includes(token));
      assert.ok(mail.html.includes(`https://app.ciphercheck.org/?resetToken=${token}`));
    });

    test("Full password reset lifecycle: request, token match, hash update, session revocation, and token one-time use", async () => {
      const email = `recovery-flow-${Date.now()}@example.com`;
      const initialPassword = "InitialPassword123!";
      const newPassword = "UpdatedPassword987!";

      const initialHash = await hashPassword(initialPassword);
      const user = await createUser(email, initialHash);

      // Create an active session for this user
      const { sessionId } = await createSession(user.id);
      const activeSession = await findSession(sessionId);
      assert.ok(activeSession);
      assert.equal(activeSession.user.id, user.id);

      // 1. Generate reset token (1 hour)
      const resetToken = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
      const tokenAssigned = await setPasswordResetToken(email, resetToken, expiresAt);
      assert.equal(tokenAssigned, true);

      // 2. Perform reset with new password
      const newHash = await hashPassword(newPassword);
      const resetResult = await resetPasswordWithToken(resetToken, newHash);
      assert.ok(resetResult);
      assert.equal(resetResult.id, user.id);

      // 3. Confirm password verification: new matches, old fails
      const updatedUser = await findUserByEmail(email);
      assert.equal(await verifyPassword(newPassword, updatedUser.passwordHash), true);
      assert.equal(await verifyPassword(initialPassword, updatedUser.passwordHash), false);

      // 4. Token cannot be reused (one-time use)
      const reusedResult = await resetPasswordWithToken(resetToken, newHash);
      assert.equal(reusedResult, null);

      // 5. Existing sessions are strictly revoked upon password reset
      const revokedSession = await findSession(sessionId);
      assert.equal(revokedSession, null);
    });

    test("Expired password reset token is strictly rejected", async () => {
      const email = `expired-reset-${Date.now()}@example.com`;
      const hash = await hashPassword("AuditPass123!");
      const user = await createUser(email, hash);

      const expiredToken = crypto.randomBytes(32).toString("hex");
      const pastExpires = new Date(Date.now() - 5 * 60 * 1000); // 5 mins ago
      await setPasswordResetToken(user.id, expiredToken, pastExpires);

      const newHash = await hashPassword("NewPass123456!");
      const result = await resetPasswordWithToken(expiredToken, newHash);
      assert.equal(result, null);
    });

    test("Non-existent identifier returns false when assigning reset token", async () => {
      const nonExistentEmail = "nobody-registered-here-999@example.com";
      const result = await setPasswordResetToken(nonExistentEmail, "any-token", new Date());
      assert.equal(result, false);
    });
  });

  describe("4. Security Protections & Credential Isolation", () => {
    test("Rate limiter throttles excessive requests after 5 attempts", () => {
      const testIp = "198.51.100.99";
      resetRateLimit(`forgot:${testIp}`);

      for (let i = 0; i < 5; i++) {
        const rate = checkRateLimit(`forgot:${testIp}`);
        assert.equal(rate.allowed, true);
      }

      const blocked = checkRateLimit(`forgot:${testIp}`);
      assert.equal(blocked.allowed, false);
      assert.ok(blocked.resetInSeconds > 0);

      resetRateLimit(`forgot:${testIp}`);
    });

    test("Unconfigured SMTP throws clean error without exposing credentials", async () => {
      delete process.env.SMTP_HOST;
      delete process.env.SMTP_USER;
      delete process.env.SMTP_PASS;

      await assert.rejects(
        async () => sendVerificationEmail("user@example.com", "token123"),
        /SMTP service is not configured/
      );

      await assert.rejects(
        async () => sendPasswordResetEmail("user@example.com", "token123"),
        /SMTP service is not configured/
      );
    });
  });

  describe("5. Verification URL Construction & 403 Forbidden Prevention", () => {
    test("transformAppHost maps private ais-dev hosts to public ais-pre hosts", () => {
      const devHost = "ais-dev-owl7r4bq4jnsb6d7xo4xig-981323894956.europe-west2.run.app";
      const expectedPreHost = "ais-pre-owl7r4bq4jnsb6d7xo4xig-981323894956.europe-west2.run.app";
      assert.equal(transformAppHost(devHost), expectedPreHost);

      // Port preservation
      assert.equal(transformAppHost(`${devHost}:443`), `${expectedPreHost}:443`);

      // Preserves normal production and preview hosts
      assert.equal(transformAppHost("app.ciphercheck.org"), "app.ciphercheck.org");
      assert.equal(transformAppHost(expectedPreHost), expectedPreHost);
      assert.equal(transformAppHost("localhost:3000"), "localhost:3000");
    });

    test("sanitizeAppUrl converts ais-dev URLs to public ais-pre preview URLs", () => {
      const devUrl = "https://ais-dev-owl7r4bq4jnsb6d7xo4xig-981323894956.europe-west2.run.app";
      const preUrl = "https://ais-pre-owl7r4bq4jnsb6d7xo4xig-981323894956.europe-west2.run.app";
      assert.equal(sanitizeAppUrl(devUrl), preUrl);
      assert.equal(sanitizeAppUrl(`${devUrl}/`), preUrl);
      assert.equal(sanitizeAppUrl("https://ciphercheck.org"), "https://ciphercheck.org");
    });

    test("getBaseUrl maps incoming request with ais-dev origin to public ais-pre URL", () => {
      const req = {
        headers: {
          origin: "https://ais-dev-owl7r4bq4jnsb6d7xo4xig-981323894956.europe-west2.run.app",
        },
      };
      const url = getBaseUrl(req);
      assert.equal(url, "https://ais-pre-owl7r4bq4jnsb6d7xo4xig-981323894956.europe-west2.run.app");
      assert.ok(!url.includes("ais-dev-"), "Link must not contain private ais-dev host that yields 403");
    });

    test("getBaseUrl maps incoming x-forwarded-host ais-dev to public ais-pre URL", () => {
      const req = {
        headers: {
          "x-forwarded-host": "ais-dev-owl7r4bq4jnsb6d7xo4xig-981323894956.europe-west2.run.app",
          "x-forwarded-proto": "https",
        },
      };
      const url = getBaseUrl(req);
      assert.equal(url, "https://ais-pre-owl7r4bq4jnsb6d7xo4xig-981323894956.europe-west2.run.app");
    });

    test("getBaseUrl prioritizes explicit PUBLIC_URL or SHARED_APP_URL over private origin", () => {
      process.env.PUBLIC_URL = "https://public.ciphercheck.org";
      const req = {
        headers: {
          origin: "https://ais-dev-owl7r4bq4jnsb6d7xo4xig-981323894956.europe-west2.run.app",
        },
      };
      const url = getBaseUrl(req);
      assert.equal(url, "https://public.ciphercheck.org");
    });

    test("sendVerificationEmail generates accessible public URL and properly encodes token query", async () => {
      process.env.SMTP_HOST = "smtp.example.com";
      process.env.SMTP_USER = "notifications@ciphercheck.org";
      process.env.SMTP_PASS = "super-secret-smtp-pass";

      const sentMails = [];
      setCustomTransporter({
        sendMail: async (mailOptions) => {
          sentMails.push(mailOptions);
          return { messageId: "msg-123" };
        },
        verify: async () => true,
      });

      const token = "special+token/with=special&chars==";
      const rawDevUrl = "https://ais-dev-owl7r4bq4jnsb6d7xo4xig-981323894956.europe-west2.run.app";

      await sendVerificationEmail("target@example.com", token, rawDevUrl);
      assert.equal(sentMails.length, 1);
      const mail = sentMails[0];

      // Verifies dev origin is sanitized to public preview origin
      assert.ok(!mail.text.includes("ais-dev-"), "Verification email text must not use ais-dev URL");
      assert.ok(!mail.html.includes("ais-dev-"), "Verification email html must not use ais-dev URL");
      assert.ok(mail.text.includes("ais-pre-"), "Verification email text must use ais-pre URL");
      assert.ok(mail.html.includes("ais-pre-"), "Verification email html must use ais-pre URL");

      // Verifies token encoding
      const encodedToken = encodeURIComponent(token);
      assert.ok(mail.text.includes(`?verifyToken=${encodedToken}`));
      assert.ok(mail.html.includes(`?verifyToken=${encodedToken}`));
    });
  });
});
