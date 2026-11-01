import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { createApp } from "../server.js";
import {
  inspectUrlTarget,
  classifyAssessment,
  checkThreatIntelRateLimit,
} from "../server-threat-intel.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Read ciphercheck/script.js content for VM-based frontend tests
const scriptPath = path.join(__dirname, "..", "ciphercheck", "script.js");
const scriptContent = fs.readFileSync(scriptPath, "utf-8");

// =============================================================================
// Helper: DOM Mock for Frontend Testing
// =============================================================================

class MockElement {
  constructor(tagName = "div") {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this._innerHTML = "";
    this._textContent = "";
    this.attributes = {};
    this.style = {};
    this.dataset = {};
    this.listeners = {};
    this.hidden = false;
    this.disabled = false;
    this.value = "";
    this.className = "";
  }

  setAttribute(k, v) {
    this.attributes[k] = String(v);
  }

  getAttribute(k) {
    return this.attributes[k] ?? null;
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  addEventListener(event, fn) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(fn);
  }

  trigger(event, data = {}) {
    for (const fn of this.listeners[event] || []) {
      fn(data);
    }
  }

  get innerHTML() {
    if (this.children.length > 0) {
      return this.children.map((c) => c.outerHTML).join("");
    }
    return this._innerHTML;
  }

  set innerHTML(val) {
    this._innerHTML = val;
    this.children = [];
  }

  get outerHTML() {
    const attrParts = [];
    if (this.className) attrParts.push(`class="${this.className}"`);
    for (const [k, v] of Object.entries(this.attributes)) {
      attrParts.push(`${k}="${v}"`);
    }
    const attrStr = attrParts.length > 0 ? ` ${attrParts.join(" ")}` : "";
    return `<${this.tagName.toLowerCase()}${attrStr}>${this.innerHTML}</${this.tagName.toLowerCase()}>`;
  }

  get textContent() {
    return this._textContent;
  }

  set textContent(val) {
    this._textContent = val;
  }
}

function createFrontendSandbox(fetchImplementation) {
  const elements = {
    urlInput: new MockElement("input"),
    analyzeUrlButton: new MockElement("button"),
    urlResults: new MockElement("div"),
    urlErrorStatus: new MockElement("div"),
    urlVerdictCard: new MockElement("div"),
    urlVerdictTitle: new MockElement("div"),
    urlVerdictSummary: new MockElement("div"),
    urlFindingCount: new MockElement("div"),
    urlFactsGrid: new MockElement("div"),
    urlFindingsList: new MockElement("ul"),
    urlFindingsCounter: new MockElement("span"),
    copyUrlReportBtn: new MockElement("button"),
    copyUrlFeedback: new MockElement("div"),
    saveUrlReportBtn: new MockElement("button"),
    saveUrlReportLabel: new MockElement("span"),
    urlVerdictCategoryTag: new MockElement("span"),
    urlVerdictConfidence: new MockElement("span"),
    urlVerdictLimitations: new MockElement("span"),
    urlProvidersSection: new MockElement("div"),
    urlProvidersSyncStatus: new MockElement("span"),
    urlProvidersGrid: new MockElement("div"),
    urlIntelMatchesSection: new MockElement("div"),
    urlIntelMatchesCounter: new MockElement("span"),
    urlIntelMatchesList: new MockElement("ul"),
    urlRawEvidenceJson: new MockElement("pre"),
  };

  elements.urlResults.hidden = true;

  const sandbox = {
    document: {
      getElementById: (id) => elements[id] || null,
      querySelectorAll: (sel) => (sel === ".sample-url-btn" ? [] : []),
      querySelector: () => null,
      createElement: (tag) => new MockElement(tag),
      documentElement: { setAttribute: () => {}, getAttribute: () => null },
      addEventListener: () => {},
    },
    window: {
      matchMedia: () => ({ matches: false, addEventListener: () => {} }),
      dispatchEvent: () => true,
    },
    localStorage: {
      getItem: () => null,
      setItem: () => {},
    },
    CustomEvent: class CustomEvent {
      constructor(type, init = {}) {
        this.type = type;
        this.detail = init.detail;
      }
    },
    crypto: globalThis.crypto,
    URL: globalThis.URL,
    Date: globalThis.Date,
    console,
    fetch: fetchImplementation,
  };

  vm.createContext(sandbox);
  vm.runInContext(
    scriptContent + `\nif (typeof initUrlChecker === 'function') { initUrlChecker(); }`,
    sandbox
  );

  return { sandbox, elements };
}

// =============================================================================
// SUITE 1: Express Route Integration Tests (/api/url/inspect)
// =============================================================================

describe("Threat Intel Regression Suite — Part 1: Express Route Integration Tests", () => {
  let server;
  let baseUrl;

  before(async () => {
    process.env.TEST_MODE = "true";
    const app = await createApp();
    assert.ok(app, "Express app should be created successfully");
    await new Promise((resolve) => {
      server = app.listen(0, "127.0.0.1", () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  test("1.1 Rejects private IPv4 addresses with HTTP 400 and explicit SSRF block response", async () => {
    const targets = [
      "http://192.168.1.100/login",
      "http://10.0.0.1/admin",
      "http://172.16.5.4/dashboard",
    ];

    for (const target of targets) {
      const resp = await fetch(`${baseUrl}/api/url/inspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target }),
      });

      assert.equal(resp.status, 400, `Expected 400 for ${target}`);
      const body = await resp.json();
      assert.equal(body.blocked, true, "Response must include blocked: true");
      assert.match(body.error, /SSRF Protection/i, "Error message must cite SSRF Protection");
      assert.ok(body.reason, "Response must explain the block reason");
    }
  });

  test("1.2 Rejects loopback and cloud metadata addresses with HTTP 400 and SSRF block", async () => {
    const targets = [
      "http://127.0.0.1:8080/metrics",
      "http://localhost:3000/api/health",
      "http://169.254.169.254/latest/meta-data", // AWS/GCP link-local metadata
      "http://0.0.0.0:80",
    ];

    for (const target of targets) {
      const resp = await fetch(`${baseUrl}/api/url/inspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target }),
      });

      assert.equal(resp.status, 400, `Expected 400 for ${target}`);
      const body = await resp.json();
      assert.equal(body.blocked, true);
      assert.match(body.error, /SSRF Protection/i);
    }
  });

  test("1.3 Rejects decimal and hex IP representations used to bypass naive filters", async () => {
    const targets = [
      "http://2130706433/", // 127.0.0.1 in decimal notation
      "http://0x7f000001/", // 127.0.0.1 in hex notation
    ];

    for (const target of targets) {
      const resp = await fetch(`${baseUrl}/api/url/inspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target }),
      });

      assert.equal(resp.status, 400, `Expected 400 for ${target}`);
      const body = await resp.json();
      assert.equal(body.blocked, true);
      assert.match(body.error, /SSRF Protection/i);
    }
  });

  test("1.4 Handles missing, empty, or whitespace URL with HTTP 400 (not 500)", async () => {
    const testCases = [
      {},
      { url: "" },
      { url: "   " },
      { url: null },
      { url: 12345 },
    ];

    for (const bodyData of testCases) {
      const resp = await fetch(`${baseUrl}/api/url/inspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bodyData),
      });

      assert.equal(resp.status, 400);
      const data = await resp.json();
      assert.match(data.error, /valid URL string is required/i);
      assert.notEqual(data.success, true);
    }
  });

  test("1.5 Handles client-side pseudo-protocols with HTTP 400 and unsupportedProtocol: true (not 500)", async () => {
    const pseudoProtocols = [
      "javascript:alert(1)",
      "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
      "file:///etc/passwd",
      "blob:http://example.com/uuid",
      "about:blank",
    ];

    for (const target of pseudoProtocols) {
      const resp = await fetch(`${baseUrl}/api/url/inspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target }),
      });

      assert.equal(resp.status, 400, `Expected 400 for ${target}`);
      const body = await resp.json();
      assert.equal(body.unsupportedProtocol, true, "Must have unsupportedProtocol: true");
      assert.match(body.reason, /Pseudo-protocols/i, "Reason must cite pseudo-protocols");
      assert.notEqual(body.success, true, "Must not indicate success");
    }
  });

  test("1.6 Enforces rate limiting on repeated requests and returns HTTP 429", async () => {
    // Unique IP header to isolate this rate-limit test
    const testIp = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;
    const headers = {
      "Content-Type": "application/json",
      "X-Forwarded-For": testIp,
    };

    let rateLimited = false;
    let rateLimitBody = null;

    // Up to 35 requests; limit is configured at 30 requests per minute
    for (let i = 0; i < 35; i++) {
      const resp = await fetch(`${baseUrl}/api/url/inspect`, {
        method: "POST",
        headers,
        body: JSON.stringify({ url: "https://example.com" }),
      });

      if (resp.status === 429) {
        rateLimited = true;
        rateLimitBody = await resp.json();
        break;
      }
    }

    assert.equal(rateLimited, true, "Request exceeding rate limit must return HTTP 429");
    assert.match(rateLimitBody.error, /rate limit exceeded/i);
    assert.ok(typeof rateLimitBody.resetInSeconds === "number" && rateLimitBody.resetInSeconds > 0);
  });

  test("1.7 Unexpected server errors are never silently converted into success", async () => {
    // Send invalid malformed JSON
    const resp = await fetch(`${baseUrl}/api/url/inspect`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "INVALID_JSON_BODY{",
    });

    assert.equal(resp.status, 400);
    const text = await resp.text();
    assert.ok(!text.includes('"success":true'), "Must never report success on malformed request");
  });
});

// =============================================================================
// SUITE 2: Frontend Provider Lifecycle & Card Transition Tests
// =============================================================================

describe("Threat Intel Regression Suite — Part 2: Frontend Provider Lifecycle Tests", () => {
  test("2.1 Initial in-flight state sets QUERYING and STANDBY before fetch resolves", async () => {
    let fetchCalled = false;
    const slowFetch = () => {
      fetchCalled = true;
      return new Promise(() => {}); // never resolves
    };

    const { elements } = createFrontendSandbox(slowFetch);
    elements.urlInput.value = "https://example.com";
    elements.analyzeUrlButton.trigger("click");

    assert.equal(fetchCalled, true, "fetch should have been invoked");
    assert.equal(elements.urlProvidersSyncStatus.textContent, "Connecting to threat intelligence feeds...");
    assert.ok(elements.urlProvidersGrid.innerHTML.includes("QUERYING..."), "Grid must show QUERYING...");
    assert.ok(elements.urlProvidersGrid.innerHTML.includes("STANDBY"), "Grid must show STANDBY");
  });

  test("2.2 SSRF Block response transitions all 4 cards to BLOCKED (SSRF) and leaves no card in QUERYING or STANDBY", async () => {
    const ssrfFetch = async () => ({
      ok: false,
      status: 400,
      json: async () => ({
        error: "SSRF Protection: Threat lookup blocked for internal, private, or prohibited host address.",
        reason: "Private IP address 192.168.1.1 is prohibited.",
        blocked: true,
      }),
    });

    const { elements } = createFrontendSandbox(ssrfFetch);
    elements.urlInput.value = "http://192.168.1.1/secret";
    elements.analyzeUrlButton.trigger("click");

    // Allow promise chain to resolve
    await new Promise((r) => setTimeout(r, 20));

    const gridHtml = elements.urlProvidersGrid.innerHTML;
    assert.ok(!gridHtml.includes("QUERYING..."), "No card may remain in QUERYING...");
    assert.ok(!gridHtml.includes("STANDBY"), "No card may remain in STANDBY");

    // Verify all 4 provider cards reflect BLOCKED (SSRF)
    const matches = gridHtml.match(/BLOCKED \(SSRF\)/g);
    assert.ok(matches && matches.length === 4, `All 4 provider cards must display BLOCKED (SSRF), found ${matches?.length}`);

    assert.equal(elements.urlProvidersSyncStatus.textContent, "External feeds skipped (SSRF safety policy)");
    assert.equal(elements.urlVerdictCategoryTag.textContent, "Local Heuristics (Private Network Host)");
  });

  test("2.3 Rate Limit response (HTTP 429) transitions all 4 cards to RATE LIMITED", async () => {
    const rateLimitFetch = async () => ({
      ok: false,
      status: 429,
      json: async () => ({
        error: "Threat intelligence rate limit exceeded. Please wait 45 seconds.",
        resetInSeconds: 45,
      }),
    });

    const { elements } = createFrontendSandbox(rateLimitFetch);
    elements.urlInput.value = "https://example.com/ratelimit";
    elements.analyzeUrlButton.trigger("click");

    await new Promise((r) => setTimeout(r, 20));

    const gridHtml = elements.urlProvidersGrid.innerHTML;
    assert.ok(!gridHtml.includes("QUERYING..."), "No card may remain in QUERYING...");
    assert.ok(!gridHtml.includes("STANDBY"), "No card may remain in STANDBY");

    const matches = gridHtml.match(/RATE LIMITED/g);
    assert.ok(matches && matches.length === 4, `All 4 cards must display RATE LIMITED, found ${matches?.length}`);
    assert.equal(elements.urlProvidersSyncStatus.textContent, "Threat lookups rate-limited");
    assert.equal(elements.urlVerdictCategoryTag.textContent, "Local Heuristics (Rate Limit Active)");
  });

  test("2.4 Network failure transitions all 4 cards to UNAVAILABLE", async () => {
    const networkFailFetch = async () => {
      throw new Error("Failed to fetch: network unreachable");
    };

    const { elements } = createFrontendSandbox(networkFailFetch);
    elements.urlInput.value = "https://example.com/offline";
    elements.analyzeUrlButton.trigger("click");

    await new Promise((r) => setTimeout(r, 20));

    const gridHtml = elements.urlProvidersGrid.innerHTML;
    assert.ok(!gridHtml.includes("QUERYING..."), "No card may remain in QUERYING...");
    assert.ok(!gridHtml.includes("STANDBY"), "No card may remain in STANDBY");

    const matches = gridHtml.match(/UNAVAILABLE/g);
    assert.ok(matches && matches.length === 4, `All 4 cards must display UNAVAILABLE, found ${matches?.length}`);
    assert.equal(elements.urlProvidersSyncStatus.textContent, "Threat feeds unreachable (local heuristics active)");
    assert.equal(elements.urlVerdictCategoryTag.textContent, "Local Heuristics (External Feeds Unavailable)");
  });

  test("2.5 Successful response transitions each provider card to terminal state accurately", async () => {
    const successFetch = async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        target: { url: "https://bad-example.com/malware" },
        inspectionTime: new Date().toISOString(),
        fromCache: false,
        summary: {
          queriedProviders: 2,
          maliciousMatches: 1,
          hasConfirmedThreat: true,
        },
        providers: {
          urlhaus: {
            providerName: "URLhaus (Abuse.ch)",
            status: "malicious",
            details: "Confirmed malware distribution point",
            reference: "https://urlhaus.abuse.ch/url/12345/",
            observationTime: new Date().toISOString(),
          },
          cloudflareDns: {
            providerName: "Cloudflare Security DNS",
            status: "no_dns_record",
            details: "Domain name does not exist (NXDOMAIN)",
          },
          googleSafeBrowsing: {
            providerName: "Google Safe Browsing",
            status: "unconfigured",
            details: "Safe Browsing API key not configured on server",
          },
          virusTotal: {
            providerName: "VirusTotal v3",
            status: "unconfigured",
            details: "VirusTotal API key not configured on server",
          },
        },
        verdict: {
          badgeLevel: "danger",
          category: "Confirmed Threat (High Severity)",
          categoryKey: "malicious",
          title: "CONFIRMED ACTIVE THREAT",
          summary: "Identified by external intelligence feeds.",
          confidence: "High Confidence",
          limitations: "Standard intelligence coverage applies.",
        },
      }),
    });

    const { elements } = createFrontendSandbox(successFetch);
    elements.urlInput.value = "https://bad-example.com/malware";
    elements.analyzeUrlButton.trigger("click");

    await new Promise((r) => setTimeout(r, 20));

    const gridHtml = elements.urlProvidersGrid.innerHTML;
    assert.ok(!gridHtml.includes("QUERYING..."), "No card may remain in QUERYING...");
    assert.ok(!gridHtml.includes("STANDBY"), "No card may remain in STANDBY");

    assert.ok(gridHtml.includes("MALICIOUS"), "URLhaus card must show MALICIOUS");
    assert.ok(gridHtml.includes("NXDOMAIN (NO DNS)"), "Cloudflare card must show NXDOMAIN (NO DNS)");
    assert.ok(gridHtml.includes("NOT CONFIGURED"), "Unconfigured cards must show NOT CONFIGURED");

    assert.equal(elements.urlVerdictTitle.textContent, "CONFIRMED ACTIVE THREAT");
    assert.equal(elements.urlIntelMatchesSection.style.display, "block", "Confirmed threat matches list should be shown");
  });

  test("2.6 Client-side pseudo-protocols bypass remote fetch and render NOT APPLICABLE on all cards", async () => {
    let fetchCalled = false;
    const recordingFetch = async () => {
      fetchCalled = true;
      return { ok: true, status: 200, json: async () => ({}) };
    };

    const { elements } = createFrontendSandbox(recordingFetch);
    elements.urlInput.value = "javascript:alert(document.domain)";
    elements.analyzeUrlButton.trigger("click");

    await new Promise((r) => setTimeout(r, 10));

    assert.equal(fetchCalled, false, "Remote fetch must NOT be called for pseudo-protocols");
    const gridHtml = elements.urlProvidersGrid.innerHTML;
    assert.ok(!gridHtml.includes("QUERYING..."), "No card may remain in QUERYING...");
    assert.ok(!gridHtml.includes("STANDBY"), "No card may remain in STANDBY");

    const matches = gridHtml.match(/NOT APPLICABLE/g);
    assert.ok(matches && matches.length === 4, `All 4 cards must display NOT APPLICABLE, found ${matches?.length}`);
    assert.match(elements.urlProvidersSyncStatus.textContent, /not applicable/i);
    assert.match(elements.urlRawEvidenceJson.textContent, /isPseudoProtocol/i);
  });
});

// =============================================================================
// SUITE 3: Asynchronous Request Sequencing & Race Condition Tests
// =============================================================================

describe("Threat Intel Regression Suite — Part 3: Asynchronous Request Sequencing Tests", () => {
  test("3.1 Scenario A: Older successful request resolving AFTER newer scan does NOT overwrite newer verdict or cards", async () => {
    let resolveFirst;
    let resolveSecond;

    const promise1 = new Promise((resolve) => {
      resolveFirst = resolve;
    });
    const promise2 = new Promise((resolve) => {
      resolveSecond = resolve;
    });

    let callCount = 0;
    const controllableFetch = async (_url, options) => {
      callCount++;
      const body = JSON.parse(options.body);
      if (body.url.includes("scan-one")) {
        return promise1;
      } else {
        return promise2;
      }
    };

    const { elements } = createFrontendSandbox(controllableFetch);

    // 1. Trigger Scan 1 (target: scan-one, malicious)
    elements.urlInput.value = "https://scan-one.example.com";
    elements.analyzeUrlButton.trigger("click");

    // 2. Trigger Scan 2 (target: scan-two, clean)
    elements.urlInput.value = "https://scan-two.example.com";
    elements.analyzeUrlButton.trigger("click");

    assert.equal(callCount, 2, "Both scans should have initiated fetch");

    // 3. Resolve Scan 2 FIRST with a Clean verdict
    resolveSecond({
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        target: { url: "https://scan-two.example.com" },
        summary: { queriedProviders: 2, maliciousMatches: 0, hasConfirmedThreat: false },
        providers: {
          urlhaus: { providerName: "URLhaus", status: "no_match", details: "No active threat records." },
          cloudflareDns: { providerName: "Cloudflare Security DNS", status: "no_match", details: "Domain resolves normally." },
          googleSafeBrowsing: { providerName: "Google Safe Browsing", status: "unconfigured" },
          virusTotal: { providerName: "VirusTotal v3", status: "unconfigured" },
        },
        verdict: {
          badgeLevel: "safe",
          category: "No Confirmed Threat Indicators",
          categoryKey: "clean",
          title: "NO THREAT INDICATORS FOUND",
          summary: "Scan two evaluated as clean.",
        },
      }),
    });

    await new Promise((r) => setTimeout(r, 20));

    // Verify Scan 2 state is rendered
    assert.equal(elements.urlVerdictTitle.textContent, "NO THREAT INDICATORS FOUND");
    assert.equal(elements.urlVerdictCategoryTag.textContent, "No Confirmed Threat Indicators");
    assert.ok(elements.urlProvidersGrid.innerHTML.includes("NO MATCH"));

    // 4. Resolve Scan 1 LATER with Malicious verdict
    resolveFirst({
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        target: { url: "https://scan-one.example.com" },
        summary: { queriedProviders: 2, maliciousMatches: 1, hasConfirmedThreat: true },
        providers: {
          urlhaus: { providerName: "URLhaus", status: "malicious", details: "CONFIRMED MALWARE DISTRIBUTOR" },
          cloudflareDns: { providerName: "Cloudflare Security DNS", status: "no_match" },
          googleSafeBrowsing: { providerName: "Google Safe Browsing", status: "unconfigured" },
          virusTotal: { providerName: "VirusTotal v3", status: "unconfigured" },
        },
        verdict: {
          badgeLevel: "danger",
          category: "Confirmed Threat (High Severity)",
          categoryKey: "malicious",
          title: "CONFIRMED ACTIVE THREAT — SCAN ONE",
          summary: "Stale scan one malicious report.",
        },
      }),
    });

    await new Promise((r) => setTimeout(r, 30));

    // ASSERT: Scan 1's late resolution MUST NOT have overwritten Scan 2!
    assert.equal(
      elements.urlVerdictTitle.textContent,
      "NO THREAT INDICATORS FOUND",
      "Stale Scan 1 response must not overwrite Scan 2's verdict title"
    );
    assert.equal(
      elements.urlVerdictCategoryTag.textContent,
      "No Confirmed Threat Indicators",
      "Stale Scan 1 response must not overwrite Scan 2's category tag"
    );
    assert.ok(
      !elements.urlProvidersGrid.innerHTML.includes("MALICIOUS"),
      "Stale Scan 1 MALICIOUS provider card must not overwrite Scan 2 provider grid"
    );
    assert.ok(
      !elements.urlRawEvidenceJson.textContent.includes("scan-one"),
      "Evidence inspector must not display Scan 1 data"
    );
  });

  test("3.2 Scenario B: Older failed request rejecting AFTER newer scan succeeds does NOT overwrite verdict with failure", async () => {
    let rejectFirst;
    let resolveSecond;

    const promise1 = new Promise((_, reject) => {
      rejectFirst = reject;
    });
    const promise2 = new Promise((resolve) => {
      resolveSecond = resolve;
    });

    const controllableFetch = async (_url, options) => {
      const body = JSON.parse(options.body);
      return body.url.includes("fail-first") ? promise1 : promise2;
    };

    const { elements } = createFrontendSandbox(controllableFetch);

    // 1. Trigger Scan 1 (will fail)
    elements.urlInput.value = "https://fail-first.example.com";
    elements.analyzeUrlButton.trigger("click");

    // 2. Trigger Scan 2 (will succeed)
    elements.urlInput.value = "https://success-second.example.com";
    elements.analyzeUrlButton.trigger("click");

    // 3. Resolve Scan 2 successfully
    resolveSecond({
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        summary: { queriedProviders: 2, maliciousMatches: 0 },
        providers: {
          urlhaus: { providerName: "URLhaus", status: "no_match" },
          cloudflareDns: { providerName: "Cloudflare Security DNS", status: "no_match" },
          googleSafeBrowsing: { providerName: "Google Safe Browsing", status: "unconfigured" },
          virusTotal: { providerName: "VirusTotal v3", status: "unconfigured" },
        },
        verdict: {
          badgeLevel: "safe",
          category: "Verified Clean Target",
          title: "CLEAN SCAN TWO",
          summary: "Scan two verified.",
        },
      }),
    });

    await new Promise((r) => setTimeout(r, 20));
    assert.equal(elements.urlVerdictTitle.textContent, "CLEAN SCAN TWO");

    // 4. Reject Scan 1 with network error
    rejectFirst(new Error("Network timeout on scan one"));

    await new Promise((r) => setTimeout(r, 30));

    // ASSERT: Scan 1's error must NOT overwrite Scan 2's clean result
    assert.equal(
      elements.urlVerdictTitle.textContent,
      "CLEAN SCAN TWO",
      "Stale rejection must not overwrite successful scan title"
    );
    assert.notEqual(
      elements.urlVerdictCategoryTag.textContent,
      "Local Heuristics (External Feeds Unavailable)",
      "Stale rejection must not downgrade Scan 2 into unavailable feeds"
    );
    assert.ok(
      !elements.urlProvidersGrid.innerHTML.includes("UNAVAILABLE"),
      "Cards must not be flipped to UNAVAILABLE by older rejected request"
    );
  });

  test("3.3 Scenario C: Older request completing while newer scan is loading does NOT clear loading state", async () => {
    let resolveFirst;
    const promise1 = new Promise((resolve) => {
      resolveFirst = resolve;
    });

    const controllableFetch = async (_url, options) => {
      const body = JSON.parse(options.body);
      if (body.url.includes("first-request")) {
        return promise1;
      }
      // Second request stays in flight
      return new Promise(() => {});
    };

    const { elements } = createFrontendSandbox(controllableFetch);

    // 1. Scan 1 starts
    elements.urlInput.value = "https://first-request.example.com";
    elements.analyzeUrlButton.trigger("click");

    // 2. Scan 2 starts immediately
    elements.urlInput.value = "https://second-request-pending.example.com";
    elements.analyzeUrlButton.trigger("click");

    // Verify Scan 2 is in initial loading state
    assert.equal(elements.urlProvidersSyncStatus.textContent, "Connecting to threat intelligence feeds...");
    assert.ok(elements.urlProvidersGrid.innerHTML.includes("QUERYING..."));

    // 3. Scan 1 completes while Scan 2 is still waiting
    resolveFirst({
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        summary: { queriedProviders: 2, maliciousMatches: 0 },
        providers: {
          urlhaus: { providerName: "URLhaus", status: "no_match" },
          cloudflareDns: { providerName: "Cloudflare Security DNS", status: "no_match" },
          googleSafeBrowsing: { providerName: "Google Safe Browsing", status: "unconfigured" },
          virusTotal: { providerName: "VirusTotal v3", status: "unconfigured" },
        },
        verdict: {
          category: "Done Scan 1",
          title: "SCAN ONE TERMINATED",
        },
      }),
    });

    await new Promise((r) => setTimeout(r, 30));

    // ASSERT: Scan 2 must STILL be in loading state
    assert.equal(
      elements.urlProvidersSyncStatus.textContent,
      "Connecting to threat intelligence feeds...",
      "Scan 2's sync status must remain in-flight"
    );
    assert.ok(
      elements.urlProvidersGrid.innerHTML.includes("QUERYING..."),
      "Scan 2 must retain QUERYING... indicator while in flight"
    );
    assert.notEqual(
      elements.urlVerdictTitle.textContent,
      "SCAN ONE TERMINATED",
      "Scan 1 must not terminate Scan 2's pending scan"
    );
  });

  test("3.4 Scenario D: Pseudo-protocol scan followed by late-resolving prior network request preserves NOT APPLICABLE", async () => {
    let resolvePendingNetworkRequest;
    const networkPromise = new Promise((resolve) => {
      resolvePendingNetworkRequest = resolve;
    });

    const controllableFetch = async () => networkPromise;

    const { elements } = createFrontendSandbox(controllableFetch);

    // 1. Start network scan
    elements.urlInput.value = "https://network-site.example.com";
    elements.analyzeUrlButton.trigger("click");

    // 2. User quickly inspects a pseudo-protocol bookmarklet
    elements.urlInput.value = "javascript:void(window.location='https://attacker.com')";
    elements.analyzeUrlButton.trigger("click");

    // Verify pseudo-protocol rendered NOT APPLICABLE immediately
    assert.ok(elements.urlProvidersGrid.innerHTML.includes("NOT APPLICABLE"));
    assert.match(elements.urlRawEvidenceJson.textContent, /isPseudoProtocol/i);

    // 3. Late network response from request 1 arrives
    resolvePendingNetworkRequest({
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        providers: {
          urlhaus: { providerName: "URLhaus", status: "no_match" },
          cloudflareDns: { providerName: "Cloudflare Security DNS", status: "no_match" },
          googleSafeBrowsing: { providerName: "Google Safe Browsing", status: "unconfigured" },
          virusTotal: { providerName: "VirusTotal v3", status: "unconfigured" },
        },
        verdict: {
          title: "NETWORK SCAN COMPLETED",
          category: "Clean",
        },
      }),
    });

    await new Promise((r) => setTimeout(r, 30));

    // ASSERT: Pseudo-protocol result must NOT be overwritten by late network scan
    const matches = elements.urlProvidersGrid.innerHTML.match(/NOT APPLICABLE/g);
    assert.ok(matches && matches.length === 4, "Cards must remain in NOT APPLICABLE state");
    assert.match(elements.urlRawEvidenceJson.textContent, /isPseudoProtocol/i);
    assert.notEqual(elements.urlVerdictTitle.textContent, "NETWORK SCAN COMPLETED");
  });
});

// =============================================================================
// SUITE 4: Verified Corrections & Regression Safeguards
// =============================================================================

describe("Threat Intel Regression Suite — Part 4: Verified Threat-Intel Logic Safeguards", () => {
  test("4.1 URLhaus exact matching takes absolute precedence over host-level records", () => {
    const intel = {
      target: {
        rawInput: "https://example.com/clean-path",
        normalizedUrl: "https://example.com/clean-path",
        hostname: "example.com",
      },
      providers: {
        urlhaus: {
          providerName: "URLhaus",
          status: "no_match",
          matchLevel: "exact_url",
          details: "Exact URL is not listed as active malware.",
        },
        cloudflareDns: {
          providerName: "Cloudflare Security DNS",
          status: "no_match",
        },
      },
      summary: {
        queriedProviders: 2,
        maliciousMatches: 0,
        hasConfirmedThreat: false,
      },
    };

    const classified = classifyAssessment("safe", [], intel);
    assert.equal(classified.badgeLevel, "clean");
    assert.equal(classified.categoryKey, "no-indicators");
    assert.match(classified.title, /NO OBVIOUS INDICATORS/i);
  });

  test("4.2 Shared platforms (github.com) treat host-level findings as contextual and never trigger malicious verdict", () => {
    const intel = {
      target: {
        rawInput: "https://raw.githubusercontent.com/legitimate-user/project/main/readme.md",
        normalizedUrl: "https://raw.githubusercontent.com/legitimate-user/project/main/readme.md",
        hostname: "raw.githubusercontent.com",
      },
      providers: {
        urlhaus: {
          providerName: "URLhaus",
          status: "suspicious",
          matchLevel: "host",
          isSharedPlatform: true,
          details: "Shared hosting platform raw.githubusercontent.com has host-level records, but exact URL is not listed.",
        },
        cloudflareDns: {
          providerName: "Cloudflare Security DNS",
          status: "no_match",
        },
      },
      summary: {
        queriedProviders: 2,
        maliciousMatches: 0,
        hasConfirmedThreat: false,
      },
    };

    const classified = classifyAssessment("safe", [], intel);
    assert.notEqual(classified.badgeLevel, "danger", "Shared platform host finding must never produce danger");
    assert.notEqual(classified.categoryKey, "malicious", "Shared platform host finding must never produce malicious");
  });

  test("4.3 Cloudflare NXDOMAIN status 3 produces no_dns_record and unverified outcome (never safe)", () => {
    const intel = {
      target: {
        rawInput: "https://this-domain-does-not-exist-123456789.com",
        normalizedUrl: "https://this-domain-does-not-exist-123456789.com",
        hostname: "this-domain-does-not-exist-123456789.com",
      },
      providers: {
        urlhaus: {
          providerName: "URLhaus",
          status: "no_match",
        },
        cloudflareDns: {
          providerName: "Cloudflare Security DNS",
          status: "no_dns_record",
          details: "Domain name does not exist (NXDOMAIN)",
        },
      },
      summary: {
        queriedProviders: 2,
        maliciousMatches: 0,
        hasConfirmedThreat: false,
      },
    };

    const classified = classifyAssessment("safe", [], intel);
    assert.notEqual(classified.badgeLevel, "safe", "NXDOMAIN target must not be marked safe");
    assert.equal(classified.badgeLevel, "low", "NXDOMAIN target should be unverified low badge");
    assert.equal(classified.categoryKey, "unverified", "Category must be unverified");
    assert.match(classified.title, /UNVERIFIED|Domain Does Not Resolve/i);
  });

  test("4.4 SSRF engine prevents outbound requests to internal IP addresses before provider invocation", async () => {
    const privateTargets = [
      "http://127.0.0.1/",
      "http://10.1.2.3/",
      "http://172.20.0.1/",
      "http://192.168.0.1/",
      "http://169.254.169.254/",
    ];

    for (const target of privateTargets) {
      await assert.rejects(
        async () => {
          await inspectUrlTarget(target);
        },
        (err) => {
          assert.match(err.message, /prohibited|Private|Loopback|Link-local/i);
          return true;
        },
        `inspectUrlTarget should reject ${target} immediately`
      );
    }
  });
});
