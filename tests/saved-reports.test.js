import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import {
  createUser,
  hashPassword,
  createSession,
  redactSensitiveUrl,
  saveReport,
  getSavedReports,
  getSavedReportById,
  deleteSavedReport,
  clearAllSavedReports,
} from "../server-auth.js";

describe("Phase 4: Security Dashboard & Saved Scan History", () => {
  let userA;
  let userB;

  before(async () => {
    const pwHash = await hashPassword("ComplexPass123!Safe");
    userA = await createUser(`dashboard-user-a-${Date.now()}@example.org`, pwHash, "Alice");
    userB = await createUser(`dashboard-user-b-${Date.now()}@example.org`, pwHash, "Bob");
  });

  describe("URL & Credential Redaction", () => {
    test("redactSensitiveUrl removes authority credentials", () => {
      const sensitive = "https://admin:superSecret123@portal.internal.corp/admin/tools";
      const redacted = redactSensitiveUrl(sensitive);
      assert.ok(!redacted.includes("superSecret123"));
      assert.ok(!redacted.includes("admin:"));
      assert.ok(redacted.includes("[REDACTED]@portal.internal.corp"));
    });

    test("redactSensitiveUrl redacts sensitive query parameters", () => {
      const sensitive =
        "https://api.partner.example/v1/checkout?token=sec_9876543210fedcba&user_id=42&apiKey=live_xyz999&session=sess_abc123&sort=asc";
      const redacted = redactSensitiveUrl(sensitive);
      assert.ok(!redacted.includes("sec_9876543210fedcba"), "token must be redacted");
      assert.ok(!redacted.includes("live_xyz999"), "apiKey must be redacted");
      assert.ok(!redacted.includes("sess_abc123"), "session must be redacted");
      assert.ok(redacted.includes("sort=asc"), "harmless param should be preserved");
      assert.ok(redacted.includes("user_id=42"), "user_id should be preserved");
    });

    test("redactSensitiveUrl preserves benign query params and paths", () => {
      const benign = "https://en.wikipedia.org/wiki/Computer_security?lang=en&view=desktop#History";
      const redacted = redactSensitiveUrl(benign);
      assert.equal(redacted, benign);
    });

    test("redactSensitiveUrl handles schemeless and malformed inputs gracefully", () => {
      const raw = "subdomain.example.com/test?token=secretKey123";
      const redacted = redactSensitiveUrl(raw);
      assert.ok(!redacted.includes("secretKey123"));
      assert.ok(redacted.includes("[REDACTED]"));
    });
  });

  describe("Report Persistence & Isolation", () => {
    let reportA1;
    let reportA2;
    let reportB1;

    test("saveReport saves analysis and populates metadata correctly", async () => {
      const mockAnalysisA1 = {
        isValid: true,
        urlParts: {
          rawUrl: "https://admin:pword@suspicious-bank.com.attacker.com/login?token=abc123xyz",
          protocol: "https:",
          hostname: "suspicious-bank.com.attacker.com",
          registeredDomain: "attacker.com",
        },
        verdict: {
          level: "high",
          title: "Deceptive Brand Domain Structure",
          summary: "Brand token appears in subdomain of an unrelated registrable domain.",
        },
        facts: [
          { label: "Destination Host", value: "suspicious-bank.com.attacker.com" },
          { label: "Registered Domain", value: "attacker.com" },
        ],
        findings: [
          {
            id: "deceptive_brand_subdomain",
            title: "Brand impersonation attempt",
            severity: "high",
            explanation: "Target contains known brand bank in subdomain.",
            whyItMatters: "Deceives victims into trusting the host.",
          },
        ],
      };

      reportA1 = await saveReport(userA.id, mockAnalysisA1);
      assert.ok(reportA1.id, "Report should have an ID");
      assert.equal(reportA1.userId, userA.id);
      assert.equal(reportA1.riskLevel, "high");
      assert.equal(reportA1.hostname, "suspicious-bank.com.attacker.com");
      assert.equal(reportA1.registeredDomain, "attacker.com");
      assert.equal(reportA1.findingsCount, 1);
      assert.ok(!reportA1.redactedUrl.includes("pword"), "Redacted URL must not contain credentials");
      assert.ok(!reportA1.redactedUrl.includes("abc123xyz"), "Redacted URL must not contain query token");
    });

    test("saveReport saves additional clean report for User A", async () => {
      const mockAnalysisClean = {
        isValid: true,
        urlParts: {
          rawUrl: "https://www.wikipedia.org/wiki/Cryptography",
          protocol: "https:",
          hostname: "www.wikipedia.org",
          registeredDomain: "wikipedia.org",
        },
        verdict: {
          level: "clean",
          title: "No Obvious Structural Red Flags",
          summary: "Syntactic structure aligns with typical web links.",
        },
        facts: [
          { label: "Host", value: "www.wikipedia.org" },
          { label: "Registered Domain", value: "wikipedia.org" },
        ],
        findings: [],
      };

      reportA2 = await saveReport(userA.id, mockAnalysisClean);
      assert.ok(reportA2.id);
      assert.equal(reportA2.riskLevel, "clean");
      assert.equal(reportA2.findingsCount, 0);
    });

    test("saveReport saves report for User B", async () => {
      const mockAnalysisB = {
        isValid: true,
        urlParts: {
          rawUrl: "http://192.168.1.1:8080/setup",
          protocol: "http:",
          hostname: "192.168.1.1",
          registeredDomain: "192.168.1.1",
        },
        verdict: {
          level: "medium",
          title: "IP Address Host and Unencrypted Transport",
          summary: "Host uses raw IP address instead of domain name.",
        },
        facts: [
          { label: "Host", value: "192.168.1.1" },
          { label: "Protocol", value: "http:" },
        ],
        findings: [
          {
            id: "ip_address_host",
            title: "IP address used as host",
            severity: "medium",
            explanation: "Raw IP prevents domain identity verification.",
            whyItMatters: "Commonly used by short-lived attack infrastructure.",
          },
        ],
      };

      reportB1 = await saveReport(userB.id, mockAnalysisB);
      assert.ok(reportB1.id);
      assert.equal(reportB1.userId, userB.id);
      assert.equal(reportB1.riskLevel, "medium");
    });

    test("Strict Isolation: User B cannot see or access User A's reports", async () => {
      const resultB = await getSavedReports(userB.id);
      assert.equal(resultB.pagination.total, 1, "User B should only see their own 1 report");
      assert.equal(resultB.reports[0].id, reportB1.id);

      // Direct ID inspection isolation
      const forbiddenReport = await getSavedReportById(reportA1.id, userB.id);
      assert.equal(forbiddenReport, null, "User B must not be able to retrieve User A's report by ID");
    });

    test("Strict Isolation: User B cannot delete User A's report", async () => {
      const deleteAttempt = await deleteSavedReport(reportA1.id, userB.id);
      assert.equal(deleteAttempt, false, "User B cannot delete User A's report");

      // Verify User A's report is still intact
      const intactReport = await getSavedReportById(reportA1.id, userA.id);
      assert.ok(intactReport, "User A's report must remain intact after unauthorized delete attempt");
      assert.equal(intactReport.id, reportA1.id);
    });

    test("Dashboard statistics calculation", async () => {
      const resA = await getSavedReports(userA.id);
      assert.equal(resA.pagination.total, 2);
      assert.equal(resA.stats.total, 2);
      assert.equal(resA.stats.byRisk.high, 1);
      assert.equal(resA.stats.byRisk.clean, 1);
      assert.equal(resA.stats.byRisk.low, 0);
      assert.equal(resA.stats.byRisk.medium, 0);
    });

    test("Filtering by risk level", async () => {
      const cleanOnly = await getSavedReports(userA.id, { riskLevel: "clean" });
      assert.equal(cleanOnly.reports.length, 1);
      assert.equal(cleanOnly.reports[0].riskLevel, "clean");

      const highOnly = await getSavedReports(userA.id, { riskLevel: "high" });
      assert.equal(highOnly.reports.length, 1);
      assert.equal(highOnly.reports[0].riskLevel, "high");

      const lowOnly = await getSavedReports(userA.id, { riskLevel: "low" });
      assert.equal(lowOnly.reports.length, 0);
    });

    test("Search filtering by hostname and URL", async () => {
      const searchWiki = await getSavedReports(userA.id, { search: "wikipedia" });
      assert.equal(searchWiki.reports.length, 1);
      assert.equal(searchWiki.reports[0].hostname, "www.wikipedia.org");

      const searchAttacker = await getSavedReports(userA.id, { search: "attacker.com" });
      assert.equal(searchAttacker.reports.length, 1);
      assert.equal(searchAttacker.reports[0].registeredDomain, "attacker.com");

      const searchNonExistent = await getSavedReports(userA.id, { search: "non-existent-domain-xyz" });
      assert.equal(searchNonExistent.reports.length, 0);
    });

    test("Pagination bounds and limits", async () => {
      const pageSlice = await getSavedReports(userA.id, { limit: 1, offset: 0 });
      assert.equal(pageSlice.reports.length, 1);
      assert.equal(pageSlice.pagination.total, 2);
      assert.equal(pageSlice.pagination.limit, 1);
      assert.equal(pageSlice.pagination.offset, 0);

      const pageSlice2 = await getSavedReports(userA.id, { limit: 1, offset: 1 });
      assert.equal(pageSlice2.reports.length, 1);
      assert.notEqual(pageSlice.reports[0].id, pageSlice2.reports[0].id);
    });

    test("Delete single report removes only targeted report", async () => {
      const deleted = await deleteSavedReport(reportA2.id, userA.id);
      assert.equal(deleted, true);

      const checkGone = await getSavedReportById(reportA2.id, userA.id);
      assert.equal(checkGone, null);

      const afterDelete = await getSavedReports(userA.id);
      assert.equal(afterDelete.pagination.total, 1);
      assert.equal(afterDelete.reports[0].id, reportA1.id);
    });

    test("Clear all reports for User A clears only User A and leaves User B unaffected", async () => {
      const clearedCount = await clearAllSavedReports(userA.id);
      assert.equal(clearedCount, 1);

      const userAPostClear = await getSavedReports(userA.id);
      assert.equal(userAPostClear.pagination.total, 0);
      assert.equal(userAPostClear.stats.total, 0);

      // Verify User B's report is still intact
      const userBReports = await getSavedReports(userB.id);
      assert.equal(userBReports.pagination.total, 1);
      assert.equal(userBReports.reports[0].id, reportB1.id);
    });
  });

  describe("HTTP API Endpoints & Authorization", () => {
    let tokenA;
    let tokenB;

    before(async () => {
      const emailA = `http-user-a-${Date.now()}@example.org`;
      const emailB = `http-user-b-${Date.now()}@example.org`;

      const regA = await fetch("http://127.0.0.1:3000/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailA, password: "SecurePassword123!", nickname: "AliceHTTP" }),
      });
      const dataA = await regA.json();
      tokenA = dataA.token;

      const regB = await fetch("http://127.0.0.1:3000/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailB, password: "SecurePassword123!", nickname: "BobHTTP" }),
      });
      const dataB = await regB.json();
      tokenB = dataB.token;
    });

    test("Unauthenticated requests to /api/reports are rejected with 401", async () => {
      const getRes = await fetch("http://127.0.0.1:3000/api/reports");
      assert.equal(getRes.status, 401);

      const postRes = await fetch("http://127.0.0.1:3000/api/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysis: { isValid: true } }),
      });
      assert.equal(postRes.status, 401);

      const delRes = await fetch("http://127.0.0.1:3000/api/reports/any-id", {
        method: "DELETE",
      });
      assert.equal(delRes.status, 401);

      const clearRes = await fetch("http://127.0.0.1:3000/api/reports", {
        method: "DELETE",
      });
      assert.equal(clearRes.status, 401);
    });

    test("POST /api/reports rejects invalid or missing analysis with 400", async () => {
      const res = await fetch("http://127.0.0.1:3000/api/reports", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${tokenA}`,
        },
        body: JSON.stringify({ analysis: { invalid: true } }),
      });
      assert.equal(res.status, 400);
    });

    let httpSavedReportId;

    test("POST /api/reports creates report and returns 201 with redacted URL", async () => {
      const res = await fetch("http://127.0.0.1:3000/api/reports", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${tokenA}`,
        },
        body: JSON.stringify({
          analysis: {
            isValid: true,
            urlParts: {
              rawUrl: "https://user:password123@secure-portal.example.org/dashboard?auth=token_secret_123",
              protocol: "https:",
              hostname: "secure-portal.example.org",
              registeredDomain: "example.org",
            },
            verdict: {
              level: "low",
              title: "Low Risk Structure",
              summary: "Observed typical domain structure.",
            },
            facts: [{ label: "Host", value: "secure-portal.example.org" }],
            findings: [],
          },
        }),
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.ok(data.report.id);
      httpSavedReportId = data.report.id;
      assert.ok(!data.report.redactedUrl.includes("password123"));
      assert.ok(!data.report.redactedUrl.includes("token_secret_123"));
    });

    test("GET /api/reports retrieves user reports and accurate stats", async () => {
      const res = await fetch("http://127.0.0.1:3000/api/reports", {
        headers: {
          Authorization: `Bearer ${tokenA}`,
        },
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.ok(data.reports.length >= 1);
      assert.equal(data.stats.total, data.reports.length);
    });

    test("GET /api/reports/:id allows author to inspect findings", async () => {
      const res = await fetch(`http://127.0.0.1:3000/api/reports/${httpSavedReportId}`, {
        headers: {
          Authorization: `Bearer ${tokenA}`,
        },
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.equal(data.report.id, httpSavedReportId);
    });

    test("GET /api/reports/:id isolates reports: User B cannot access User A's report", async () => {
      const res = await fetch(`http://127.0.0.1:3000/api/reports/${httpSavedReportId}`, {
        headers: {
          Authorization: `Bearer ${tokenB}`,
        },
      });

      assert.equal(res.status, 404);
    });

    test("DELETE /api/reports/:id isolates reports: User B cannot delete User A's report", async () => {
      const res = await fetch(`http://127.0.0.1:3000/api/reports/${httpSavedReportId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${tokenB}`,
        },
      });

      assert.equal(res.status, 404);
    });

    test("DELETE /api/reports/:id allows author to delete own report", async () => {
      const res = await fetch(`http://127.0.0.1:3000/api/reports/${httpSavedReportId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${tokenA}`,
        },
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
    });
  });
});

