import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import {
  createUser,
  hashPassword,
  getUserRecommendationStatus,
  saveUserRecommendationStatus,
  updateUserRecommendationAction,
} from "../server-auth.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load script.js into VM sandbox to access recommendation functions
const scriptPath = path.join(__dirname, "..", "ciphercheck", "script.js");
const scriptContent = fs.readFileSync(scriptPath, "utf-8");

const sandbox = {
  document: {
    addEventListener: () => {},
    getElementById: () => null,
    querySelectorAll: () => [],
    documentElement: { setAttribute: () => {}, getAttribute: () => null },
    querySelector: () => null,
  },
  window: {
    matchMedia: () => ({ matches: false, addEventListener: () => {} }),
    addEventListener: () => {},
    dispatchEvent: () => {},
  },
  localStorage: {
    getItem: () => null,
    setItem: () => {},
  },
  crypto: globalThis.crypto,
  URL: globalThis.URL,
  Date: globalThis.Date,
  console,
};

vm.createContext(sandbox);
const exported = vm.runInContext(
  scriptContent +
    `\nvar __exported = {
      generateSecurityRecommendations,
      SEVERITY_WEIGHT,
      analyzePassword,
      analyzeUrl
    }; __exported;`,
  sandbox
);

const { generateSecurityRecommendations, SEVERITY_WEIGHT, analyzePassword, analyzeUrl } = exported;

describe("Phase 5: Personal Security Center & Actionable Security Recommendations", () => {
  describe("1. Recommendation Generation from Genuine Findings", () => {
    test("Generates baseline security hygiene guidance when no analysis has been run", () => {
      const recs = generateSecurityRecommendations();
      assert.ok(Array.isArray(recs), "Should return an array");
      assert.ok(recs.length >= 2, "Should provide initial hygiene guides");

      const guideIds = recs.map((r) => r.id);
      assert.ok(guideIds.includes("rec-guide-audit-password"), "Should include password audit guide");
      assert.ok(guideIds.includes("rec-guide-check-url"), "Should include link checker guide");
      assert.ok(guideIds.includes("rec-guide-generate-password"), "Should include password generator guide");

      // Verify every recommendation has required properties
      recs.forEach((rec) => {
        assert.ok(rec.id, "Recommendation must have an id");
        assert.ok(rec.title, "Recommendation must have a title");
        assert.ok(rec.severity, "Recommendation must have a severity");
        assert.ok(rec.category, "Recommendation must have a category");
        assert.ok(rec.explanation, "Recommendation must have an explanation");
        assert.ok(rec.actionLabel, "Recommendation must have an actionLabel");
        assert.ok(rec.targetId, "Recommendation must have a targetId");
        assert.equal(typeof rec.isAddressed, "boolean");
        assert.equal(typeof rec.isDismissed, "boolean");
      });
    });

    test("Detects weak password findings and generates high-severity entropy recommendation", () => {
      // Analyze a known weak password
      const pwResult = analyzePassword("abc");
      const recs = generateSecurityRecommendations({ passwordAnalysis: pwResult });

      const entropyRec = recs.find((r) => r.id === "rec-password-entropy");
      assert.ok(entropyRec, "Weak password must trigger rec-password-entropy");
      assert.equal(entropyRec.severity, "high");
      assert.equal(entropyRec.category, "password");
      assert.equal(entropyRec.targetId, "generatorPanel");
      assert.ok(entropyRec.explanation.includes("/100"), "Explanation should cite actual score");

      const lengthRec = recs.find((r) => r.id === "rec-password-length");
      assert.ok(lengthRec, "Short password (<12 chars) must trigger rec-password-length");
      assert.equal(lengthRec.severity, "high");
    });

    test("Detects predictable patterns in passwords and generates pattern-resistance recommendation", () => {
      const pwResult = analyzePassword("password12345");
      const recs = generateSecurityRecommendations({ passwordAnalysis: pwResult });

      const patternRec = recs.find((r) => r.id === "rec-password-patterns");
      assert.ok(patternRec, "Predictable sequence or dictionary word must trigger rec-password-patterns");
      assert.equal(patternRec.severity, "medium");
      assert.ok(patternRec.explanation.length > 10);
      assert.equal(patternRec.targetId, "generatorPanel");
    });

    test("Acknowledges high-entropy passwords with info verification recommendation", () => {
      const pwResult = analyzePassword("K#9vX$2mQ!7zL*4pT@8w");
      assert.ok(pwResult.score >= 85, "Must score Very Strong");
      const recs = generateSecurityRecommendations({ passwordAnalysis: pwResult });

      const strongRec = recs.find((r) => r.id === "rec-password-strong");
      assert.ok(strongRec, "Strong password must trigger positive verification guidance");
      assert.equal(strongRec.severity, "info");
      assert.ok(!recs.some((r) => r.id === "rec-password-entropy"), "No weak entropy rec for strong password");
    });

    test("Detects high-risk URL indicators and generates high-priority link avoidance guidance", () => {
      // Authority credential trick: https://apple.com@evil-site.net/auth
      const urlResult = analyzeUrl("https://apple.com@evil-site.net/auth");
      assert.equal(urlResult.verdict.level, "high");

      const recs = generateSecurityRecommendations({ urlAnalysis: urlResult });
      const urlRec = recs.find((r) => r.id === "rec-url-high-risk");
      assert.ok(urlRec, "High-risk URL must trigger rec-url-high-risk");
      assert.equal(urlRec.severity, "high");
      assert.equal(urlRec.category, "url");
      assert.equal(urlRec.targetId, "urlPanel");
      assert.ok(urlRec.explanation.toLowerCase().includes("deceptive"), "Grounded in actual structural markers");
    });

    test("Detects medium-risk URL indicators and generates cautionary recommendation", () => {
      // Unencrypted HTTP with non-standard port triggers medium risk
      const urlResult = analyzeUrl("http://example.com:8080/login");
      assert.equal(urlResult.verdict.level, "medium");
      const recs = generateSecurityRecommendations({ urlAnalysis: urlResult });

      const urlRec = recs.find((r) => r.id === "rec-url-medium-risk");
      assert.ok(urlRec, "Medium risk URL must trigger rec-url-medium-risk");
      assert.equal(urlRec.severity, "medium");
      assert.equal(urlRec.category, "url");
    });

    test("Detects low-risk URL indicators and generates minor notice recommendation", () => {
      // Single warning (unencrypted HTTP) triggers low risk
      const urlResult = analyzeUrl("http://example.com/login");
      assert.equal(urlResult.verdict.level, "low");
      const recs = generateSecurityRecommendations({ urlAnalysis: urlResult });

      const urlRec = recs.find((r) => r.id === "rec-url-low-risk");
      assert.ok(urlRec, "Low risk URL must trigger rec-url-low-risk");
      assert.equal(urlRec.severity, "low");
      assert.equal(urlRec.category, "url");
    });

    test("Confirms clean HTTPS URL with informational scope disclosure", () => {
      const urlResult = analyzeUrl("https://en.wikipedia.org/wiki/Computer_security");
      assert.equal(urlResult.verdict.level, "clean");

      const recs = generateSecurityRecommendations({ urlAnalysis: urlResult });
      const cleanRec = recs.find((r) => r.id === "rec-url-clean");
      assert.ok(cleanRec, "Clean URL must trigger rec-url-clean");
      assert.equal(cleanRec.severity, "info");
      assert.ok(cleanRec.explanation.includes("wikipedia.org"));
    });

    test("Summarizes saved scan history risk patterns without alleging user compromise", () => {
      const stats = { total: 4, clean: 2, low: 0, medium: 1, high: 1 };
      const recs = generateSecurityRecommendations({ savedReportsStats: stats });

      const historyRec = recs.find((r) => r.id === "rec-history-flagged-links");
      assert.ok(historyRec, "Flagged history scans must trigger rec-history-flagged-links");
      assert.equal(historyRec.severity, "medium");
      assert.equal(historyRec.targetId, "dashboardPanel");
      assert.ok(historyRec.explanation.includes("1 high-risk and 1 elevated-risk"));

      // Verify no alarmist claims of compromise
      assert.ok(!historyRec.explanation.toLowerCase().includes("compromised"));
      assert.ok(!historyRec.explanation.toLowerCase().includes("hacked"));
      assert.ok(!historyRec.explanation.toLowerCase().includes("infected"));
    });

    test("Identifies unencrypted HTTP links in saved reports history", () => {
      const stats = { total: 2, clean: 1, low: 1, medium: 0, high: 0 };
      const reports = [
        { id: "1", url: "https://secure.example.com", redactedUrl: "https://secure.example.com" },
        { id: "2", url: "http://insecure.example.com", redactedUrl: "http://insecure.example.com" },
      ];
      const recs = generateSecurityRecommendations({ savedReportsStats: stats, savedReports: reports });

      const httpRec = recs.find((r) => r.id === "rec-history-unencrypted-http");
      assert.ok(httpRec, "Unencrypted HTTP in history should trigger guidance");
      assert.equal(httpRec.severity, "low");
      assert.equal(httpRec.category, "history");
    });

    test("Confirms clean saved scan history profile when all scans are clean", () => {
      const stats = { total: 5, clean: 5, low: 0, medium: 0, high: 0 };
      const recs = generateSecurityRecommendations({ savedReportsStats: stats });

      const cleanHistoryRec = recs.find((r) => r.id === "rec-history-clean-profile");
      assert.ok(cleanHistoryRec, "Clean history should trigger positive hygiene confirmation");
      assert.equal(cleanHistoryRec.severity, "info");
    });
  });

  describe("2. Robust Handling of Empty and Incomplete Data", () => {
    test("Handles empty objects, nulls, and undefined parameters gracefully", () => {
      assert.doesNotThrow(() => generateSecurityRecommendations({}));
      assert.doesNotThrow(() => generateSecurityRecommendations(null));
      assert.doesNotThrow(() => generateSecurityRecommendations({ passwordAnalysis: {} }));
      assert.doesNotThrow(() => generateSecurityRecommendations({ passwordAnalysis: { score: "bad", length: null } }));
      assert.doesNotThrow(() => generateSecurityRecommendations({ urlAnalysis: { isValid: false } }));
      assert.doesNotThrow(() => generateSecurityRecommendations({ savedReportsStats: "invalid" }));
      assert.doesNotThrow(() => generateSecurityRecommendations({ savedReports: "not-an-array" }));
      assert.doesNotThrow(() => generateSecurityRecommendations({ addressedIds: null, dismissedIds: null }));
    });
  });

  describe("3. Prioritization & Severity Sorting", () => {
    test("Orders recommendations strictly by severity (high > medium > low > info) and addressed state", () => {
      const pwResult = analyzePassword("abc"); // triggers high entropy & length recs
      const urlResult = analyzeUrl("http://example.com"); // triggers medium rec
      const recs = generateSecurityRecommendations({
        passwordAnalysis: pwResult,
        urlAnalysis: urlResult,
        addressedIds: ["rec-password-entropy"], // mark one high-severity rec addressed
      });

      // 1. Unaddressed recommendations must appear before addressed ones
      const unaddressedRecs = recs.filter((r) => !r.isAddressed);
      const addressedRecs = recs.filter((r) => r.isAddressed);

      assert.ok(unaddressedRecs.length > 0);
      assert.ok(addressedRecs.length > 0);

      // Verify that all unaddressed precede addressed
      const firstAddressedIndex = recs.findIndex((r) => r.isAddressed);
      const lastUnaddressedIndex = recs.findLastIndex((r) => !r.isAddressed);
      assert.ok(firstAddressedIndex > lastUnaddressedIndex, "All unaddressed items must precede addressed items");

      // Verify severity sorting within unaddressed items
      for (let i = 1; i < unaddressedRecs.length; i++) {
        const prevWeight = SEVERITY_WEIGHT[unaddressedRecs[i - 1].severity];
        const currWeight = SEVERITY_WEIGHT[unaddressedRecs[i].severity];
        assert.ok(prevWeight >= currWeight, `Severity must be descending: ${unaddressedRecs[i - 1].severity} >= ${unaddressedRecs[i].severity}`);
      }
    });
  });

  describe("4. Privacy & Zero-Transmission Protections", () => {
    test("Recommendations never contain the submitted plaintext password", () => {
      const secretPassword = "SuperSecret_P@ssw0rd999_NeverLeakMe";
      const pwResult = analyzePassword(secretPassword);
      const recs = generateSecurityRecommendations({ passwordAnalysis: pwResult });

      recs.forEach((rec) => {
        assert.ok(!rec.title.includes(secretPassword), "Title must never contain plaintext password");
        assert.ok(!rec.explanation.includes(secretPassword), "Explanation must never contain plaintext password");
      });
    });

    test("Recommendations never leak sensitive credentials from URL analysis", () => {
      const sensitiveUrl = "https://admin:mySecretToken123@portal.test.internal/login?token=jwt_xyz999";
      const urlResult = analyzeUrl(sensitiveUrl);
      const recs = generateSecurityRecommendations({ urlAnalysis: urlResult });

      recs.forEach((rec) => {
        assert.ok(!rec.title.includes("mySecretToken123"), "Credentials must not appear in rec title");
        assert.ok(!rec.explanation.includes("mySecretToken123"), "Credentials must not appear in rec explanation");
        assert.ok(!rec.explanation.includes("jwt_xyz999"), "Query tokens must not appear in rec explanation");
      });
    });
  });

  describe("5. Dismissal & Addressed States and Persistence", () => {
    test("Flags addressed and dismissed states accurately", () => {
      const recs = generateSecurityRecommendations({
        addressedIds: ["rec-guide-audit-password"],
        dismissedIds: ["rec-guide-generate-password"],
      });

      const auditRec = recs.find((r) => r.id === "rec-guide-audit-password");
      const genRec = recs.find((r) => r.id === "rec-guide-generate-password");
      const urlRec = recs.find((r) => r.id === "rec-guide-check-url");

      assert.equal(auditRec?.isAddressed, true);
      assert.equal(auditRec?.isDismissed, false);
      assert.equal(genRec?.isAddressed, false);
      assert.equal(genRec?.isDismissed, true);
      assert.equal(urlRec?.isAddressed, false);
      assert.equal(urlRec?.isDismissed, false);
    });

    test("Direct helper functions save and update user recommendations status", async () => {
      const testUserId = `test-user-rec-${Date.now()}`;

      // Initial state
      const initial = await getUserRecommendationStatus(testUserId);
      assert.deepEqual(initial.addressed, []);
      assert.deepEqual(initial.dismissed, []);

      // Address an item
      const afterAddress = await updateUserRecommendationAction(testUserId, "address", "rec-password-entropy");
      assert.ok(afterAddress.addressed.includes("rec-password-entropy"));
      assert.ok(!afterAddress.dismissed.includes("rec-password-entropy"));

      // Dismiss an item
      const afterDismiss = await updateUserRecommendationAction(testUserId, "dismiss", "rec-guide-check-url");
      assert.ok(afterDismiss.dismissed.includes("rec-guide-check-url"));
      assert.ok(!afterDismiss.addressed.includes("rec-guide-check-url"));

      // Unaddress an item
      const afterUnaddress = await updateUserRecommendationAction(testUserId, "unaddress", "rec-password-entropy");
      assert.ok(!afterUnaddress.addressed.includes("rec-password-entropy"));

      // Reset
      const afterReset = await updateUserRecommendationAction(testUserId, "reset");
      assert.deepEqual(afterReset.addressed, []);
      assert.deepEqual(afterReset.dismissed, []);
    });
  });

  describe("6. Backend API & Strict User Isolation", () => {
    let tokenA;
    let tokenB;

    before(async () => {
      const emailA = `rec-user-a-${Date.now()}@example.org`;
      const emailB = `rec-user-b-${Date.now()}@example.org`;

      const regA = await fetch("http://127.0.0.1:3000/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailA, password: "ComplexPass123!Secure", nickname: "AliceRec" }),
      });
      const dataA = await regA.json();
      tokenA = dataA.token;

      const regB = await fetch("http://127.0.0.1:3000/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailB, password: "ComplexPass123!Secure", nickname: "BobRec" }),
      });
      const dataB = await regB.json();
      tokenB = dataB.token;
    });

    test("Unauthenticated requests to /api/recommendations/status are rejected with 401", async () => {
      const getRes = await fetch("http://127.0.0.1:3000/api/recommendations/status");
      assert.equal(getRes.status, 401);

      const postRes = await fetch("http://127.0.0.1:3000/api/recommendations/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "address", id: "rec-test" }),
      });
      assert.equal(postRes.status, 401);
    });

    test("User A can address and dismiss recommendations via HTTP API", async () => {
      const addressRes = await fetch("http://127.0.0.1:3000/api/recommendations/status", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${tokenA}`,
        },
        body: JSON.stringify({ action: "address", id: "rec-password-entropy" }),
      });
      assert.equal(addressRes.status, 200);
      const addressData = await addressRes.json();
      assert.ok(addressData.addressed.includes("rec-password-entropy"));

      const dismissRes = await fetch("http://127.0.0.1:3000/api/recommendations/status", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${tokenA}`,
        },
        body: JSON.stringify({ action: "dismiss", id: "rec-guide-audit-password" }),
      });
      assert.equal(dismissRes.status, 200);
      const dismissData = await dismissRes.json();
      assert.ok(dismissData.dismissed.includes("rec-guide-audit-password"));
    });

    test("Strict Isolation: User B's recommendations status is completely isolated from User A", async () => {
      // User B fetches status
      const resB = await fetch("http://127.0.0.1:3000/api/recommendations/status", {
        headers: {
          Authorization: `Bearer ${tokenB}`,
        },
      });
      assert.equal(resB.status, 200);
      const dataB = await resB.json();

      // User B should NOT have User A's addressed or dismissed IDs
      assert.ok(!dataB.addressed.includes("rec-password-entropy"), "User B must not see User A's addressed recs");
      assert.ok(!dataB.dismissed.includes("rec-guide-audit-password"), "User B must not see User A's dismissed recs");

      // User B addresses a different recommendation
      const setResB = await fetch("http://127.0.0.1:3000/api/recommendations/status", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${tokenB}`,
        },
        body: JSON.stringify({ action: "address", id: "rec-user-b-only" }),
      });
      assert.equal(setResB.status, 200);

      // Verify User A still has their original state and did not get User B's state
      const resA = await fetch("http://127.0.0.1:3000/api/recommendations/status", {
        headers: {
          Authorization: `Bearer ${tokenA}`,
        },
      });
      assert.equal(resA.status, 200);
      const dataA = await resA.json();
      assert.ok(dataA.addressed.includes("rec-password-entropy"));
      assert.ok(!dataA.addressed.includes("rec-user-b-only"), "User A must not be affected by User B");
    });
  });
});
