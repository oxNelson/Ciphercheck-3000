import { test, describe, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  parseIpv4ToNumber,
  isPrivateOrReservedIpv4,
  isPrivateOrReservedIpv6,
  validateTargetHost,
  sanitizeUrlForThreatIntel,
  classifyAssessment,
  checkThreatIntelRateLimit,
  clearThreatCache,
  inspectUrlTarget,
  isSharedMultiTenantPlatform,
  SHARED_MULTI_TENANT_DOMAINS,
  queryUrlhaus,
  queryCloudflareSecurityDns,
} from "../server-threat-intel.js";
import {
  saveReport,
  getSavedReports,
  getSavedReportById,
  initDatabase,
  resetMemoryStore,
} from "../server-auth.js";

describe("1. SSRF Guard: IPv4 Representation Parsing & Validation", () => {
  test("Detects and blocks standard loopback and private IPv4 ranges", () => {
    // 127.0.0.1
    const loopback = validateTargetHost("127.0.0.1");
    assert.equal(loopback.valid, false);
    assert.match(loopback.reason, /Loopback address/);

    // 10.0.0.5
    const priv10 = validateTargetHost("10.0.0.5");
    assert.equal(priv10.valid, false);
    assert.match(priv10.reason, /Private network/);

    // 192.168.1.1
    const priv192 = validateTargetHost("192.168.1.1");
    assert.equal(priv192.valid, false);
    assert.match(priv192.reason, /Private network/);

    // 172.16.0.1 to 172.31.255.255
    const priv172 = validateTargetHost("172.20.5.1");
    assert.equal(priv172.valid, false);
    assert.match(priv172.reason, /Private network/);

    // 169.254.169.254 (Cloud metadata endpoint)
    const meta = validateTargetHost("169.254.169.254");
    assert.equal(meta.valid, false);
    assert.match(meta.reason, /Link-local \/ Cloud metadata/);

    // 0.0.0.0
    const zero = validateTargetHost("0.0.0.0");
    assert.equal(zero.valid, false);
    assert.match(zero.reason, /Zero network/);
  });

  test("Detects and blocks decimal integer IP notations (e.g. 2130706433 = 127.0.0.1)", () => {
    const num = parseIpv4ToNumber("2130706433");
    assert.equal(num, 0x7f000001);
    const check = validateTargetHost("2130706433");
    assert.equal(check.valid, false);
    assert.match(check.reason, /Loopback address/);
  });

  test("Detects and blocks hexadecimal IP notations (e.g. 0x7f000001 = 127.0.0.1)", () => {
    const check = validateTargetHost("0x7f000001");
    assert.equal(check.valid, false);
    assert.match(check.reason, /Loopback address/);
  });

  test("Detects and blocks octal dotted IP notations (e.g. 0177.0.0.1 = 127.0.0.1)", () => {
    const num = parseIpv4ToNumber("0177.0.0.1");
    assert.equal(num, 0x7f000001);
    const check = validateTargetHost("0177.0.0.1");
    assert.equal(check.valid, false);
    assert.match(check.reason, /Loopback address/);
  });

  test("Allows public routable internet IPv4 addresses", () => {
    const publicDns = validateTargetHost("8.8.8.8");
    assert.equal(publicDns.valid, true);
    assert.equal(publicDns.isIp, true);

    const quad9 = validateTargetHost("9.9.9.9");
    assert.equal(quad9.valid, true);
  });
});

describe("2. SSRF Guard: IPv6 & IPv4-Mapped Address Validation", () => {
  test("Blocks IPv6 loopback ::1 and unspecified ::", () => {
    const loop6 = validateTargetHost("::1");
    assert.equal(loop6.valid, false);
    assert.match(loop6.reason, /IPv6 loopback/);

    const bracketed = validateTargetHost("[::1]");
    assert.equal(bracketed.valid, false);

    const unspec = validateTargetHost("::");
    assert.equal(unspec.valid, false);
  });

  test("Blocks IPv4-mapped IPv6 loopback and private addresses", () => {
    const mappedLoopback = validateTargetHost("::ffff:127.0.0.1");
    assert.equal(mappedLoopback.valid, false);
    assert.match(mappedLoopback.reason, /IPv4-mapped/);

    const mappedPrivate = validateTargetHost("::ffff:192.168.1.1");
    assert.equal(mappedPrivate.valid, false);
    assert.match(mappedPrivate.reason, /IPv4-mapped/);
  });

  test("Blocks IPv6 Link-Local (fe80::) and Unique Local Addresses (fc00::)", () => {
    const linkLocal = validateTargetHost("fe80::1ff:fe23:4567:890a");
    assert.equal(linkLocal.valid, false);
    assert.match(linkLocal.reason, /Link-Local/);

    const ula = validateTargetHost("fd12:3456:789a:1::1");
    assert.equal(ula.valid, false);
    assert.match(ula.reason, /Unique Local Address/);
  });

  test("Blocks internal and reserved domain names", () => {
    const localhost = validateTargetHost("localhost");
    assert.equal(localhost.valid, false);
    assert.match(localhost.reason, /Internal host/);

    const internalMeta = validateTargetHost("metadata.google.internal");
    assert.equal(internalMeta.valid, false);
    assert.match(internalMeta.reason, /Internal host/);

    const lan = validateTargetHost("router.lan");
    assert.equal(lan.valid, false);
    assert.match(lan.reason, /Private or reserved TLD/);

    const local = validateTargetHost("server.local");
    assert.equal(local.valid, false);
    assert.match(local.reason, /Private or reserved TLD/);
  });

  test("Allows standard public domain names", () => {
    const pub = validateTargetHost("example.com");
    assert.equal(pub.valid, true);
    assert.equal(pub.hostname, "example.com");
    assert.equal(pub.isIp, false);
  });
});

describe("3. Privacy & URL Sanitization for Threat Lookups", () => {
  test("Strips basic authentication credentials from inspection target", () => {
    const res = sanitizeUrlForThreatIntel("https://admin:superSecret123@example.com/checkout");
    assert.equal(res.sanitizedUrl, "https://example.com/checkout");
    assert.equal(res.sanitizedUrl.includes("superSecret123"), false);
    assert.equal(res.sanitizedUrl.includes("admin"), false);
  });

  test("Strips query parameters to prevent leaking tokens or user identifiers", () => {
    const res = sanitizeUrlForThreatIntel("https://example.com/api/v1/user?token=eyJhbGciOi...&auth=secret#section2");
    assert.equal(res.sanitizedUrl, "https://example.com/api/v1/user");
    assert.equal(res.sanitizedUrl.includes("token"), false);
    assert.equal(res.sanitizedUrl.includes("section2"), false);
  });

  test("Generates SHA-256 fingerprint of sanitized target", () => {
    const res = sanitizeUrlForThreatIntel("https://example.com/login");
    assert.equal(typeof res.sha256Hex, "string");
    assert.equal(res.sha256Hex.length, 64);
  });

  test("Rejects unsupported protocols (javascript:, file:, ftp:)", () => {
    assert.throws(() => sanitizeUrlForThreatIntel("javascript:alert(1)"), /not supported/);
    assert.throws(() => sanitizeUrlForThreatIntel("file:///etc/passwd"), /not supported/);
  });

  test("Rejects SSRF targets during sanitization", () => {
    assert.throws(() => sanitizeUrlForThreatIntel("http://127.0.0.1/admin"), /prohibited/);
    assert.throws(() => sanitizeUrlForThreatIntel("http://169.254.169.254/latest/meta-data"), /prohibited/);
  });
});

describe("4. Evidence & Verdict Engine Categorization", () => {
  test("Category 1: Confirmed Threat when any provider reports malicious", () => {
    const threatIntel = {
      providers: {
        urlhaus: {
          provider: "urlhaus",
          providerName: "URLhaus (Abuse.ch)",
          status: "malicious",
          details: "Host listed with 4 active malware URLs",
        },
        cloudflareDns: {
          provider: "cloudflare_security_dns",
          providerName: "Cloudflare 1.1.1.2 Security DNS",
          status: "no_match",
        },
      },
    };

    const verdict = classifyAssessment("clean", [], threatIntel);
    assert.equal(verdict.category, "Confirmed Threat");
    assert.equal(verdict.categoryKey, "confirmed-threat");
    assert.equal(verdict.badgeLevel, "high");
    assert.match(verdict.summary, /URLhaus/);
  });

  test("Category 2: Suspicious / Heuristic Warning when high heuristic is detected without feed listing", () => {
    const threatIntel = {
      providers: {
        urlhaus: { status: "no_match" },
        cloudflareDns: { status: "no_match" },
      },
    };
    const heuristicFindings = [
      { id: "embedded-credentials", severity: "high", title: "Deceptive Embedded Authority (@ Symbol)" },
    ];

    const verdict = classifyAssessment("high", heuristicFindings, threatIntel);
    assert.equal(verdict.category, "Suspicious / Heuristic Warning");
    assert.equal(verdict.categoryKey, "suspicious-warning");
    assert.equal(verdict.badgeLevel, "high");
    assert.match(verdict.summary, /Deceptive structural patterns/);
  });

  test("Category 3: Unverified / Insufficient Data when heuristics are clean but providers are unconfigured or unavailable", () => {
    const threatIntel = {
      providers: {
        urlhaus: { status: "unavailable" },
        cloudflareDns: { status: "timeout" },
        safeBrowsing: { status: "unconfigured" },
        virusTotal: { status: "unconfigured" },
      },
    };

    const verdict = classifyAssessment("clean", [], threatIntel);
    assert.equal(verdict.category, "Unverified / Insufficient Data");
    assert.equal(verdict.categoryKey, "unverified");
    assert.equal(verdict.badgeLevel, "low");
    assert.match(verdict.title, /Unverified Destination/);
    assert.match(verdict.limitations, /feeds were unavailable/);
  });

  test("Category 4: No Obvious Indicators when heuristics are clean and responsive providers find no match", () => {
    const threatIntel = {
      providers: {
        urlhaus: { status: "no_match" },
        cloudflareDns: { status: "no_match" },
      },
    };

    const verdict = classifyAssessment("clean", [], threatIntel);
    assert.equal(verdict.category, "No Obvious Indicators");
    assert.equal(verdict.categoryKey, "no-indicators");
    assert.equal(verdict.badgeLevel, "clean");
    assert.match(verdict.title, /No Obvious Indicators/);
    assert.match(verdict.limitations, /does NOT establish/);
  });
});

describe("5. Rate Limiting & Cache Invalidation", () => {
  beforeEach(() => {
    clearThreatCache();
  });

  test("Allows requests within rate limit window (max 30/min)", () => {
    const ip = "test-rate-ip-1";
    for (let i = 0; i < 30; i++) {
      const res = checkThreatIntelRateLimit(ip);
      assert.equal(res.allowed, true);
    }
    // 31st request should be rejected
    const blocked = checkThreatIntelRateLimit(ip);
    assert.equal(blocked.allowed, false);
    assert.equal(blocked.remaining, 0);
    assert.ok(blocked.resetInSeconds > 0);
  });

  test("Caches inspection result and returns fromCache on subsequent query", async () => {
    const sampleUrl = "https://example.com/cached-page";
    const first = await inspectUrlTarget(sampleUrl, { timeoutMs: 1500 });
    assert.equal(first.fromCache, false);

    const second = await inspectUrlTarget(sampleUrl, { timeoutMs: 1500 });
    assert.equal(second.fromCache, true);
    assert.ok(second.cachedAt);
  });
});

describe("6. Database Persistence & Backward Compatibility", () => {
  beforeEach(async () => {
    resetMemoryStore();
  });

  test("Saves report with threat intelligence metadata and query status", async () => {
    const analysisWithIntel = {
      isValid: true,
      rawInput: "https://example.org/test?token=secretKey999",
      normalizedUrl: "https://example.org/test",
      urlParts: {
        hostname: "example.org",
        registeredDomain: "example.org",
        protocol: "https",
        port: "443",
        pathname: "/test",
      },
      verdict: {
        level: "clean",
        title: "No Obvious Indicators Detected",
        summary: "Clean heuristics and feeds.",
        categoryKey: "no-indicators",
      },
      facts: [{ label: "Host", value: "example.org" }],
      findings: [],
      threatIntelligence: {
        status: "no-indicators",
        summary: {
          queriedProviders: 2,
          maliciousMatches: 0,
          hasConfirmedThreat: false,
        },
        providers: {
          urlhaus: { status: "no_match" },
          cloudflareDns: { status: "no_match" },
        },
      },
    };

    const saved = await saveReport("user-intel-test", analysisWithIntel);
    assert.ok(saved.id);
    assert.equal(saved.threatIntelStatus, "no-indicators");
    assert.equal(saved.threatIntelMatches, 0);
    assert.equal(saved.redactedUrl.includes("secretKey999"), false);

    const fetched = await getSavedReportById(saved.id, "user-intel-test");
    assert.ok(fetched);
    assert.equal(fetched.id, saved.id);
    assert.equal(fetched.threatIntelMatches, 0);
  });

  test("Backward compatibility: seamlessly reads legacy reports lacking threat intelligence columns", async () => {
    const legacyAnalysis = {
      isValid: true,
      rawInput: "https://legacy-site.org/home",
      urlParts: {
        hostname: "legacy-site.org",
        registeredDomain: "legacy-site.org",
      },
      verdict: {
        level: "low",
        title: "Low Risk",
      },
      findings: [],
    };

    const savedLegacy = await saveReport("user-legacy-test", legacyAnalysis);
    assert.ok(savedLegacy.id);
    assert.equal(savedLegacy.threatIntelStatus, "unverified");
    assert.equal(savedLegacy.threatIntelMatches, 0);

    const list = await getSavedReports("user-legacy-test");
    assert.equal(list.reports.length, 1);
    assert.equal(list.reports[0].id, savedLegacy.id);
    assert.equal(list.reports[0].threatIntelStatus, "unverified");
  });
});

describe("7. Verified Threat-Intelligence Corrections & Regression Suite", () => {
  test("1. https://github.com/torvalds/linux is not flagged as malicious by URLhaus", () => {
    // Shared multi-tenant platform recognition
    assert.equal(isSharedMultiTenantPlatform("github.com"), true);
    assert.equal(isSharedMultiTenantPlatform("raw.githubusercontent.com"), true);

    // Simulated URLhaus response: no exact URL match, but host github.com has historical records
    const simulatedUrlhausShared = {
      provider: "urlhaus",
      providerName: "URLhaus (Abuse.ch)",
      status: "no_match",
      details: "Host is a shared multi-tenant platform (github.com). Historical platform abuse reports do not indict this specific URL.",
      evidence: {
        matchType: "shared_platform_context",
        sharedPlatform: true,
        exactUrlMatch: false,
        hostTotalUrlsFound: 100,
        hostActiveMalwareUrls: 12,
      },
    };

    const threatIntel = {
      providers: {
        urlhaus: simulatedUrlhausShared,
        cloudflareDns: {
          provider: "cloudflare_security_dns",
          providerName: "Cloudflare 1.1.1.2 Security DNS",
          status: "no_match",
          details: "Domain resolved normally without security policy intervention.",
        },
      },
    };

    const verdict = classifyAssessment("clean", [], threatIntel);
    assert.notEqual(verdict.category, "Confirmed Threat");
    assert.equal(verdict.category, "No Obvious Indicators");
    assert.equal(verdict.categoryKey, "no-indicators");
    assert.equal(verdict.badgeLevel, "clean");
  });

  test("2. Exact URLhaus match continues to contribute malicious evidence", () => {
    const exactMatchIntel = {
      providers: {
        urlhaus: {
          provider: "urlhaus",
          providerName: "URLhaus (Abuse.ch)",
          status: "malicious",
          details: "Exact URL identified in URLhaus threat feed as malware_download (online).",
          evidence: {
            matchType: "exact_url",
            queryStatus: "ok",
            urlhausId: "2489123",
            threat: "malware_download",
            urlStatus: "online",
          },
        },
        cloudflareDns: {
          provider: "cloudflare_security_dns",
          providerName: "Cloudflare 1.1.1.2 Security DNS",
          status: "no_match",
        },
      },
    };

    const verdict = classifyAssessment("clean", [], exactMatchIntel);
    assert.equal(verdict.category, "Confirmed Threat");
    assert.equal(verdict.categoryKey, "confirmed-threat");
    assert.equal(verdict.badgeLevel, "high");
    assert.match(verdict.summary, /URLhaus/);
    assert.match(verdict.confidence, /High \(Verified Threat Intelligence\)/);
  });

  test("3. Host-level match on shared platforms remains contextual; dedicated host triggers suspicious warning", () => {
    // Shared platforms return no_match when exact URL is clean
    assert.equal(isSharedMultiTenantPlatform("gitlab.com"), true);
    assert.equal(isSharedMultiTenantPlatform("pages.dev"), true);
    assert.equal(isSharedMultiTenantPlatform("vercel.app"), true);
    assert.equal(isSharedMultiTenantPlatform("drive.google.com"), true);
    assert.equal(isSharedMultiTenantPlatform("example.com"), false);

    // Dedicated host with active malware records triggers suspicious warning rather than false Confirmed Threat
    const dedicatedHostIntel = {
      providers: {
        urlhaus: {
          provider: "urlhaus",
          providerName: "URLhaus (Abuse.ch)",
          status: "suspicious",
          details: "Host has 15 recorded malware URL(s) (3 active) on URLhaus. Specific URL is not listed as active malware.",
          evidence: {
            matchType: "host_reputation",
            sharedPlatform: false,
            exactUrlMatch: false,
            activeMalwareUrls: 3,
          },
        },
        cloudflareDns: {
          provider: "cloudflare_security_dns",
          providerName: "Cloudflare 1.1.1.2 Security DNS",
          status: "no_match",
        },
      },
    };

    const verdict = classifyAssessment("clean", [], dedicatedHostIntel);
    assert.notEqual(verdict.category, "Confirmed Threat");
    assert.equal(verdict.category, "Suspicious / Heuristic Warning");
    assert.equal(verdict.categoryKey, "suspicious-warning");
    assert.equal(verdict.badgeLevel, "medium");
    assert.match(verdict.summary, /Contextual threat intelligence warnings/);
  });

  test("4. Cloudflare NXDOMAIN produces an unverified outcome (not safe, not malicious)", () => {
    const nxdomainIntel = {
      providers: {
        urlhaus: {
          provider: "urlhaus",
          providerName: "URLhaus (Abuse.ch)",
          status: "no_match",
        },
        cloudflareDns: {
          provider: "cloudflare_security_dns",
          providerName: "Cloudflare 1.1.1.2 Security DNS",
          status: "no_dns_record",
          details: "Domain does not resolve in public DNS (NXDOMAIN). No active DNS A/AAAA records found.",
          evidence: {
            dnsStatus: 3,
            statusName: "NXDOMAIN",
            unresolvable: true,
          },
        },
      },
    };

    const verdict = classifyAssessment("clean", [], nxdomainIntel);
    assert.equal(verdict.category, "Unverified / Insufficient Data");
    assert.equal(verdict.categoryKey, "unverified");
    assert.equal(verdict.badgeLevel, "low");
    assert.equal(verdict.title, "Unverified Destination (Domain Does Not Resolve)");
    assert.match(verdict.summary, /does not resolve in public DNS \(NXDOMAIN\)/);
    assert.match(verdict.limitations, /No active DNS records exist/);
  });

  test("5. Clean target with coverage retains a no-indicators outcome", () => {
    const cleanCoverageIntel = {
      providers: {
        urlhaus: {
          provider: "urlhaus",
          providerName: "URLhaus (Abuse.ch)",
          status: "no_match",
          details: "No recorded malware campaigns found for URL or host in URLhaus database.",
        },
        cloudflareDns: {
          provider: "cloudflare_security_dns",
          providerName: "Cloudflare 1.1.1.2 Security DNS",
          status: "no_match",
          details: "Domain resolved normally without security policy intervention.",
        },
        virusTotal: {
          provider: "virustotal",
          providerName: "VirusTotal v3",
          status: "no_match",
          details: "Scanned by 60 engines with 0 malicious detections.",
        },
      },
    };

    const verdict = classifyAssessment("clean", [], cleanCoverageIntel);
    assert.equal(verdict.category, "No Obvious Indicators");
    assert.equal(verdict.categoryKey, "no-indicators");
    assert.equal(verdict.badgeLevel, "clean");
    assert.equal(verdict.title, "No Obvious Indicators Detected");
    assert.match(verdict.confidence, /Standard/);
    assert.match(verdict.limitations, /Absence of detected indicators does NOT establish/);
  });

  test("6. Conflicting provider results preserve the evidence hierarchy", () => {
    // Case A: Confirmed malicious overrides NXDOMAIN (e.g. domain taken down after verified malware attack)
    const maliciousAndNxdomain = {
      providers: {
        urlhaus: {
          provider: "urlhaus",
          providerName: "URLhaus (Abuse.ch)",
          status: "malicious",
          details: "Confirmed malware download payload.",
        },
        cloudflareDns: {
          provider: "cloudflare_security_dns",
          providerName: "Cloudflare 1.1.1.2 Security DNS",
          status: "no_dns_record",
          details: "Domain does not resolve (NXDOMAIN).",
        },
      },
    };
    const verdictA = classifyAssessment("clean", [], maliciousAndNxdomain);
    assert.equal(verdictA.category, "Confirmed Threat");
    assert.equal(verdictA.categoryKey, "confirmed-threat");

    // Case B: NXDOMAIN overrides clean No Match when no confirmed malice exists
    const nxdomainAndNoMatch = {
      providers: {
        urlhaus: {
          provider: "urlhaus",
          providerName: "URLhaus (Abuse.ch)",
          status: "no_match",
        },
        cloudflareDns: {
          provider: "cloudflare_security_dns",
          providerName: "Cloudflare 1.1.1.2 Security DNS",
          status: "no_dns_record",
        },
      },
    };
    const verdictB = classifyAssessment("clean", [], nxdomainAndNoMatch);
    assert.equal(verdictB.category, "Unverified / Insufficient Data");
    assert.equal(verdictB.categoryKey, "unverified");

    // Case C: Suspicious contextual intelligence overrides clean No Match
    const suspiciousAndClean = {
      providers: {
        urlhaus: {
          provider: "urlhaus",
          providerName: "URLhaus (Abuse.ch)",
          status: "suspicious",
          details: "Host malware history.",
        },
        cloudflareDns: {
          provider: "cloudflare_security_dns",
          providerName: "Cloudflare 1.1.1.2 Security DNS",
          status: "no_match",
        },
      },
    };
    const verdictC = classifyAssessment("clean", [], suspiciousAndClean);
    assert.equal(verdictC.category, "Suspicious / Heuristic Warning");
    assert.equal(verdictC.categoryKey, "suspicious-warning");
  });

  test("7. Explicitly identifies and rejects pseudo-protocols (javascript:, data:) for external inspection", () => {
    assert.throws(
      () => sanitizeUrlForThreatIntel("javascript:alert(1)"),
      (err) => err.message.includes("Protocol 'javascript' is not supported")
    );
    assert.throws(
      () => sanitizeUrlForThreatIntel("data:text/html,<b>test</b>"),
      (err) => err.message.includes("Protocol 'data' is not supported")
    );
  });
});


