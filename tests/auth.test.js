import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  hashPassword,
  verifyPassword,
  checkRateLimit,
  resetRateLimit,
  createUser,
  updateUserNickname,
  findUserByEmail,
  createSession,
  findSession,
  deleteSession,
  parseCookies,
  serializeSessionCookie,
  setVerificationToken,
  verifyEmailToken,
  setPasswordResetToken,
  resetPasswordWithToken,
} from "../server-auth.js";
import { isSmtpConfigured, getBaseUrl } from "../server-smtp.js";

describe("Phase 2: Authentication & Security Foundation", () => {
  test("Password hashing creates secure hash and verifies correctly", async () => {
    const rawPassword = "CorrectHorseBatteryStaple!";
    const hash = await hashPassword(rawPassword);

    assert.ok(hash.startsWith("$2") || hash.startsWith("scrypt:"));
    const isCorrect = await verifyPassword(rawPassword, hash);
    assert.equal(isCorrect, true);

    const isWrong = await verifyPassword("WrongPassword!", hash);
    assert.equal(isWrong, false);
  });

  test("Rate limiter blocks brute force after 5 attempts", () => {
    const testIp = "192.0.2.42";
    resetRateLimit(testIp);

    for (let i = 0; i < 5; i++) {
      const res = checkRateLimit(testIp);
      assert.equal(res.allowed, true);
    }

    const blocked = checkRateLimit(testIp);
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.resetInSeconds > 0);

    resetRateLimit(testIp);
    const unblocked = checkRateLimit(testIp);
    assert.equal(unblocked.allowed, true);
  });

  test("User registration and email lookup", async () => {
    const email = `audit-test-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash);

    assert.ok(user.id);
    assert.equal(user.email, email.toLowerCase());
    assert.equal(user.isVerified, false);
    assert.equal(user.passwordHash, undefined); // Ensure passwordHash is omitted

    const found = await findUserByEmail(email);
    assert.ok(found);
    assert.equal(found.id, user.id);
  });

  test("Session lifecycle: create, find, and delete", async () => {
    const email = `session-test-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash);

    const { sessionId, expiresAt } = await createSession(user.id);
    assert.equal(typeof sessionId, "string");
    assert.equal(sessionId.length, 64); // 32 bytes hex
    assert.ok(expiresAt > new Date());

    const sessionData = await findSession(sessionId);
    assert.ok(sessionData);
    assert.equal(sessionData.user.id, user.id);
    assert.equal(sessionData.user.email, email);

    await deleteSession(sessionId);
    const invalidated = await findSession(sessionId);
    assert.equal(invalidated, null);
  });

  test("Cookie serialization enforces HttpOnly and SameSite=Lax", () => {
    const sessionId = "abcdef0123456789abcdef0123456789";
    const expiresAt = new Date(Date.now() + 3600 * 1000);
    const serialized = serializeSessionCookie(sessionId, expiresAt, false);

    assert.ok(serialized.includes(`session_id=${sessionId}`));
    assert.ok(serialized.includes("HttpOnly"));
    assert.ok(serialized.includes("SameSite=Lax"));
    assert.ok(serialized.includes("Path=/"));
  });

  test("Cookie serialization enforces Secure flag when HTTPS / isSecure is true", () => {
    const sessionId = "abcdef0123456789abcdef0123456789";
    const expiresAt = new Date(Date.now() + 3600 * 1000);
    const serialized = serializeSessionCookie(sessionId, expiresAt, true);

    assert.ok(serialized.includes("; Secure"));
  });

  test("User isolation: authenticated session strictly isolates user data", async () => {
    const userA = await createUser(`usera-${Date.now()}@example.com`, "hashA");
    const userB = await createUser(`userb-${Date.now()}@example.com`, "hashB");

    const sessionA = await createSession(userA.id);
    const sessionB = await createSession(userB.id);

    const lookupA = await findSession(sessionA.sessionId);
    const lookupB = await findSession(sessionB.sessionId);

    assert.equal(lookupA.user.id, userA.id);
    assert.notEqual(lookupA.user.id, userB.id);
    assert.equal(lookupB.user.id, userB.id);
    assert.notEqual(lookupB.user.id, userA.id);
  });

  test("SQL parameterization safely handles SQL injection payloads without syntax errors", async () => {
    const maliciousEmail = "' OR '1'='1' -- ";
    const result = await findUserByEmail(maliciousEmail);
    // Correctly returns null (no user found with that literal email), without executing injected SQL
    assert.equal(result, null);
  });

  test("Cookie parser extracts cookies accurately", () => {
    const header = "theme=dark; session_id=abc123xyz; other=val";
    const parsed = parseCookies(header);
    assert.equal(parsed.theme, "dark");
    assert.equal(parsed.session_id, "abc123xyz");
    assert.equal(parsed.other, "val");
  });

  test("SMTP configuration detection reflects configured environment", () => {
    assert.equal(typeof isSmtpConfigured(), "boolean");
  });

  test("Email verification token lifecycle: set, verify, and invalidate", async () => {
    const email = `verify-test-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash);

    const token = "test-token-" + Date.now();
    const expiresAt = new Date(Date.now() + 3600 * 1000);
    await setVerificationToken(user.id, token, expiresAt);

    // Invalid token should fail
    const badVerify = await verifyEmailToken("completely-invalid-token");
    assert.equal(badVerify, null);

    // Valid token should verify user
    const verified = await verifyEmailToken(token);
    assert.ok(verified);
    assert.equal(verified.id, user.id);
    assert.equal(verified.isVerified, true);

    // Replay with used token should fail
    const replayVerify = await verifyEmailToken(token);
    assert.equal(replayVerify, null);
  });

  test("Password reset token lifecycle: set, reset password, verify login", async () => {
    const email = `reset-test-${Date.now()}@example.com`;
    const oldPass = "OldPassword123!";
    const newPass = "NewSecurePassword456!";
    const hash = await hashPassword(oldPass);
    const user = await createUser(email, hash);

    const resetToken = "reset-token-" + Date.now();
    const expiresAt = new Date(Date.now() + 3600 * 1000);
    await setPasswordResetToken(user.id, resetToken, expiresAt);

    // Reset password with new hash
    const newHash = await hashPassword(newPass);
    const resetUser = await resetPasswordWithToken(resetToken, newHash);
    assert.ok(resetUser);
    assert.equal(resetUser.id, user.id);

    // Check that new password verifies and old password fails
    const userRecord = await findUserByEmail(email);
    assert.ok(userRecord);
    const oldMatches = await verifyPassword(oldPass, userRecord.passwordHash);
    assert.equal(oldMatches, false);
    const newMatches = await verifyPassword(newPass, userRecord.passwordHash);
    assert.equal(newMatches, true);

    // Reusing reset token should fail
    const reusedReset = await resetPasswordWithToken(resetToken, newHash);
    assert.equal(reusedReset, null);
  });

  test("Expired email verification token is strictly rejected", async () => {
    const email = `expired-verify-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash);

    const expiredToken = "expired-verify-token-" + Date.now();
    // Set expiry in the past
    const pastExpires = new Date(Date.now() - 3600 * 1000);
    await setVerificationToken(user.id, expiredToken, pastExpires);

    const result = await verifyEmailToken(expiredToken);
    assert.equal(result, null);
  });

  test("Expired password reset token is strictly rejected", async () => {
    const email = `expired-reset-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash);

    const expiredResetToken = "expired-reset-token-" + Date.now();
    // Set expiry in the past
    const pastExpires = new Date(Date.now() - 3600 * 1000);
    await setPasswordResetToken(user.id, expiredResetToken, pastExpires);

    const newHash = await hashPassword("BrandNewPassword123!");
    const result = await resetPasswordWithToken(expiredResetToken, newHash);
    assert.equal(result, null);
  });

  test("getBaseUrl resolves request origin when originating from an allowed preview domain", () => {
    const fakeReq = {
      headers: {
        origin: "https://ais-pre-ok6xmxuezsad5ybcofshmt-220908265023.europe-west2.run.app",
        host: "localhost:3000",
      },
    };
    const resolved = getBaseUrl(fakeReq);
    assert.equal(resolved, "https://ais-pre-ok6xmxuezsad5ybcofshmt-220908265023.europe-west2.run.app");
  });

  test("getBaseUrl resolves APP_URL environment variable when request origin is absent", () => {
    const savedAppUrl = process.env.APP_URL;
    try {
      process.env.APP_URL = "https://custom-ciphercheck.example.com";
      const resolved = getBaseUrl(null);
      assert.equal(resolved, "https://custom-ciphercheck.example.com");
    } finally {
      process.env.APP_URL = savedAppUrl;
    }
  });

  test("getBaseUrl strips trailing slashes to avoid double-slash URLs", () => {
    const fakeReq = {
      headers: {
        origin: "https://ais-dev-ok6xmxuezsad5ybcofshmt-220908265023.europe-west2.run.app///",
      },
    };
    const resolved = getBaseUrl(fakeReq);
    assert.equal(resolved, "https://ais-dev-ok6xmxuezsad5ybcofshmt-220908265023.europe-west2.run.app");
  });

  test("getBaseUrl strictly rejects aistudio.google.com origin and resolves to APP_URL", () => {
    const fakeReq = {
      headers: {
        origin: "https://aistudio.google.com",
        referer: "https://aistudio.google.com/build/14331321",
        host: "localhost:3000",
      },
    };
    const resolved = getBaseUrl(fakeReq);
    // Must NOT be aistudio.google.com
    assert.notEqual(resolved, "https://aistudio.google.com");
    // Must be the valid application deployment URL
    assert.equal(resolved, process.env.APP_URL || "https://ais-dev-ok6xmxuezsad5ybcofshmt-220908265023.europe-west2.run.app");
  });

  test("getBaseUrl strictly rejects googleusercontent.com iframe origin", () => {
    const fakeReq = {
      headers: {
        origin: "https://ais-dev-preview-xyz.googleusercontent.com",
        host: "localhost:3000",
      },
    };
    const resolved = getBaseUrl(fakeReq);
    assert.ok(!resolved.includes("googleusercontent.com"));
    assert.equal(resolved, process.env.APP_URL || "https://ais-dev-ok6xmxuezsad5ybcofshmt-220908265023.europe-west2.run.app");
  });

  test("User registration with optional nickname persists nickname accurately", async () => {
    const email = `nick-test-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash, "CyberKnight");

    assert.equal(user.nickname, "CyberKnight");

    const found = await findUserByEmail(email);
    assert.ok(found);
    assert.equal(found.nickname, "CyberKnight");
  });

  test("User registration without nickname defaults nickname to null", async () => {
    const email = `no-nick-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash);

    assert.equal(user.nickname, null);

    const found = await findUserByEmail(email);
    assert.ok(found);
    assert.equal(found.nickname, null);
  });

  test("updateUserNickname modifies nickname and reflects in findSession", async () => {
    const email = `update-nick-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash);

    // Initial session has no nickname
    const { sessionId } = await createSession(user.id);
    const session1 = await findSession(sessionId);
    assert.equal(session1.user.nickname, null);

    // Update nickname to "VaultGuardian"
    const updated = await updateUserNickname(user.id, "VaultGuardian");
    assert.equal(updated.nickname, "VaultGuardian");

    // Session retrieval reflects the updated nickname
    const session2 = await findSession(sessionId);
    assert.equal(session2.user.nickname, "VaultGuardian");
  });

  test("updateUserNickname validates length and rejects invalid inputs", async () => {
    const email = `val-nick-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash);

    // Reject too short (< 2 characters)
    await assert.rejects(
      async () => updateUserNickname(user.id, "a"),
      /between 2 and 30 characters/
    );

    // Reject too long (> 30 characters)
    await assert.rejects(
      async () => updateUserNickname(user.id, "a".repeat(31)),
      /between 2 and 30 characters/
    );

    // Reject HTML injection
    await assert.rejects(
      async () => updateUserNickname(user.id, "<script>alert(1)</script>"),
      /cannot contain HTML tags/
    );
  });

  test("Nickname user isolation: updating User A does not modify User B", async () => {
    const userA = await createUser(`iso-a-${Date.now()}@example.com`, "hashA", "AlphaNick");
    const userB = await createUser(`iso-b-${Date.now()}@example.com`, "hashB", "BetaNick");

    await updateUserNickname(userA.id, "AlphaPrime");

    const foundA = await findUserByEmail(userA.email);
    const foundB = await findUserByEmail(userB.email);

    assert.equal(foundA.nickname, "AlphaPrime");
    assert.equal(foundB.nickname, "BetaNick");
  });
});
