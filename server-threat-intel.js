"use strict";

import http from "node:http";
import https from "node:https";
import dns from "node:dns/promises";
import crypto from "node:crypto";

/**
 * Server Threat Intelligence Module for CipherCheck 3000
 *
 * Provides safe, multi-provider threat intelligence lookups without fetching
 * arbitrary user URLs. Enforces strict SSRF defense, URL credential stripping,
 * in-memory caching with TTL, and provider failure isolation.
 */

// In-memory cache: key -> { data, expiresAt }
const THREAT_CACHE = new Map();
const DEFAULT_CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes for clean/no-match
const MALICIOUS_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour for confirmed threats
const MAX_CACHE_SIZE = 5000;

// Rate limiting for URL threat inspections (in-memory token bucket)
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 30;
const rateLimitBuckets = new Map();

/**
 * Clear expired entries from cache periodically
 */
function pruneCache() {
  const now = Date.now();
  for (const [key, item] of THREAT_CACHE.entries()) {
    if (item.expiresAt <= now) {
      THREAT_CACHE.delete(key);
    }
  }
  // Enforce max size if still over limit
  if (THREAT_CACHE.size > MAX_CACHE_SIZE) {
    const keysToDelete = Array.from(THREAT_CACHE.keys()).slice(0, Math.floor(MAX_CACHE_SIZE * 0.2));
    for (const k of keysToDelete) THREAT_CACHE.delete(k);
  }
}

/**
 * Check rate limit for an identifier (e.g. client IP or user ID)
 */
export function checkThreatIntelRateLimit(identifier) {
  const now = Date.now();
  const key = String(identifier || "anonymous");
  let bucket = rateLimitBuckets.get(key);

  if (!bucket || now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
    bucket = { windowStart: now, count: 1 };
    rateLimitBuckets.set(key, bucket);
    return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW - 1, resetInSeconds: 60 };
  }

  bucket.count += 1;
  if (bucket.count > MAX_REQUESTS_PER_WINDOW) {
    const resetInSeconds = Math.max(1, Math.ceil((bucket.windowStart + RATE_LIMIT_WINDOW_MS - now) / 1000));
    return { allowed: false, remaining: 0, resetInSeconds };
  }

  return {
    allowed: true,
    remaining: MAX_REQUESTS_PER_WINDOW - bucket.count,
    resetInSeconds: Math.max(1, Math.ceil((bucket.windowStart + RATE_LIMIT_WINDOW_MS - now) / 1000)),
  };
}

/**
 * Convert any string or integer IP representation to a 32-bit unsigned number.
 * Detects decimal, octal (leading 0), hex (0x), and dotted quad.
 * Returns null if not a parseable IPv4 address.
 */
export function parseIpv4ToNumber(host) {
  if (typeof host !== "string") return null;
  const raw = host.trim();

  // Pure integer format (e.g. 2130706433 or 0x7f000001)
  if (/^\d+$/.test(raw)) {
    const num = Number(raw);
    return num >= 0 && num <= 0xffffffff ? num >>> 0 : null;
  }
  if (/^0x[0-9a-fA-F]+$/i.test(raw)) {
    const num = Number(raw);
    return num >= 0 && num <= 0xffffffff ? num >>> 0 : null;
  }

  // Dotted notation (can have 1 to 4 parts in historical implementations)
  const parts = raw.split(".");
  if (parts.length < 1 || parts.length > 4) return null;

  const numericParts = [];
  for (const part of parts) {
    if (!part) return null;
    let val;
    if (/^0x[0-9a-fA-F]+$/i.test(part)) {
      val = parseInt(part, 16);
    } else if (/^0[0-7]+$/.test(part)) {
      val = parseInt(part, 8);
    } else if (/^\d+$/.test(part)) {
      val = parseInt(part, 10);
    } else {
      return null;
    }
    if (isNaN(val) || val < 0) return null;
    numericParts.push(val);
  }

  // Construct 32-bit integer according to POSIX inet_aton rules
  let acc = 0;
  if (numericParts.length === 1) {
    acc = numericParts[0];
  } else if (numericParts.length === 2) {
    if (numericParts[0] > 0xff || numericParts[1] > 0xffffff) return null;
    acc = (numericParts[0] << 24) | numericParts[1];
  } else if (numericParts.length === 3) {
    if (numericParts[0] > 0xff || numericParts[1] > 0xff || numericParts[2] > 0xffff) return null;
    acc = (numericParts[0] << 24) | (numericParts[1] << 16) | numericParts[2];
  } else if (numericParts.length === 4) {
    for (const p of numericParts) {
      if (p > 0xff) return null;
    }
    acc = (numericParts[0] << 24) | (numericParts[1] << 16) | (numericParts[2] << 8) | numericParts[3];
  }

  return acc >>> 0;
}

/**
 * Checks if a 32-bit IPv4 address falls within private, loopback, or reserved ranges.
 */
export function isPrivateOrReservedIpv4(ipNum) {
  const byte1 = (ipNum >>> 24) & 0xff;
  const byte2 = (ipNum >>> 16) & 0xff;

  // 0.0.0.0/8 (Current network)
  if (byte1 === 0) return { blocked: true, reason: "Zero network (0.0.0.0/8)" };
  // 10.0.0.0/8 (Private RFC1918)
  if (byte1 === 10) return { blocked: true, reason: "Private network (10.0.0.0/8)" };
  // 127.0.0.0/8 (Loopback)
  if (byte1 === 127) return { blocked: true, reason: "Loopback address (127.0.0.0/8)" };
  // 100.64.0.0/10 (Carrier-Grade NAT RFC6598)
  if (byte1 === 100 && (byte2 & 0xc0) === 64) return { blocked: true, reason: "Carrier-Grade NAT (100.64.0.0/10)" };
  // 169.254.0.0/16 (Link-Local / Cloud Metadata)
  if (byte1 === 169 && byte2 === 254) return { blocked: true, reason: "Link-local / Cloud metadata (169.254.0.0/16)" };
  // 172.16.0.0/12 (Private RFC1918)
  if (byte1 === 172 && byte2 >= 16 && byte2 <= 31) return { blocked: true, reason: "Private network (172.16.0.0/12)" };
  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (byte1 === 192 && byte2 === 0 && ((ipNum >>> 8) & 0xff) === 0) return { blocked: true, reason: "IETF reserved (192.0.0.0/24)" };
  // 192.0.2.0/24 (TEST-NET-1)
  if (byte1 === 192 && byte2 === 0 && ((ipNum >>> 8) & 0xff) === 2) return { blocked: true, reason: "Documentation TEST-NET-1 (192.0.2.0/24)" };
  // 192.168.0.0/16 (Private RFC1918)
  if (byte1 === 192 && byte2 === 168) return { blocked: true, reason: "Private network (192.168.0.0/16)" };
  // 198.18.0.0/15 (Benchmarking)
  if (byte1 === 198 && (byte2 & 0xfe) === 18) return { blocked: true, reason: "Benchmark network (198.18.0.0/15)" };
  // 198.51.100.0/24 (TEST-NET-2)
  if (byte1 === 198 && byte2 === 51 && ((ipNum >>> 8) & 0xff) === 100) return { blocked: true, reason: "Documentation TEST-NET-2 (198.51.100.0/24)" };
  // 203.0.113.0/24 (TEST-NET-3)
  if (byte1 === 203 && byte2 === 0 && ((ipNum >>> 8) & 0xff) === 113) return { blocked: true, reason: "Documentation TEST-NET-3 (203.0.113.0/24)" };
  // 224.0.0.0/4 (Multicast)
  if (byte1 >= 224 && byte1 <= 239) return { blocked: true, reason: "Multicast address (224.0.0.0/4)" };
  // 240.0.0.0/4 (Reserved / Broadcast)
  if (byte1 >= 240) return { blocked: true, reason: "Reserved broadcast address (240.0.0.0/4)" };

  return { blocked: false };
}

/**
 * Checks if an IPv6 string is private, loopback, link-local, or IPv4-mapped private.
 */
export function isPrivateOrReservedIpv6(host) {
  let cleaned = host.toLowerCase().trim();
  if (cleaned.startsWith("[") && cleaned.endsWith("]")) {
    cleaned = cleaned.slice(1, -1);
  }

  // Strip zone index (%eth0, etc.)
  if (cleaned.includes("%")) {
    cleaned = cleaned.split("%")[0];
  }

  // Unspecified :: or Loopback ::1
  if (cleaned === "::" || cleaned === "0:0:0:0:0:0:0:0") {
    return { blocked: true, reason: "IPv6 unspecified address (::)" };
  }
  if (cleaned === "::1" || cleaned === "0:0:0:0:0:0:0:1") {
    return { blocked: true, reason: "IPv6 loopback address (::1)" };
  }

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
  const mappedMatch = cleaned.match(/^(?:::ffff:)?(?:0:0:0:0:0:ffff:)?(\d+\.\d+\.\d+\.\d+)$/);
  if (mappedMatch) {
    const ipv4Num = parseIpv4ToNumber(mappedMatch[1]);
    if (ipv4Num !== null) {
      const ipv4Check = isPrivateOrReservedIpv4(ipv4Num);
      if (ipv4Check.blocked) {
        return { blocked: true, reason: `IPv4-mapped ${ipv4Check.reason}` };
      }
    }
  }

  // Unique Local Address (ULA) fc00::/7 (fc00... - fdff...)
  if (/^f[cd][0-9a-f]{2}:/i.test(cleaned)) {
    return { blocked: true, reason: "IPv6 Unique Local Address (ULA fc00::/7)" };
  }

  // Link-Local fe80::/10 (fe8... - feb...)
  if (/^fe[89ab][0-9a-f]:/i.test(cleaned) || cleaned.startsWith("fe80:")) {
    return { blocked: true, reason: "IPv6 Link-Local address (fe80::/10)" };
  }

  // Site-Local fec0::/10 (deprecated)
  if (/^fe[c-f][0-9a-f]:/i.test(cleaned)) {
    return { blocked: true, reason: "IPv6 Site-Local address (fec0::/10)" };
  }

  // Multicast ff00::/8
  if (/^ff[0-9a-f]{2}:/i.test(cleaned)) {
    return { blocked: true, reason: "IPv6 Multicast address (ff00::/8)" };
  }

  // Documentation 2001:db8::/32
  if (/^2001:0?db8:/i.test(cleaned)) {
    return { blocked: true, reason: "IPv6 Documentation address (2001:db8::/32)" };
  }

  return { blocked: false };
}

/**
 * Validates target host against SSRF vulnerabilities (IPv4, IPv6, special formats, internal names).
 * Returns { valid: boolean, reason?: string, hostname: string }
 */
export function validateTargetHost(host) {
  if (typeof host !== "string" || !host.trim()) {
    return { valid: false, reason: "Target host is missing or invalid.", hostname: "" };
  }

  const normalized = host.toLowerCase().trim().replace(/\.+$/, "");

  // Reserved internal hostnames and TLDs
  const forbiddenHostnames = new Set([
    "localhost",
    "loopback",
    "broadcasthost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
  ]);
  if (forbiddenHostnames.has(normalized)) {
    return { valid: false, reason: `Internal host '${normalized}' is prohibited for threat lookups.`, hostname: normalized };
  }

  const forbiddenTlds = [".localhost", ".local", ".internal", ".lan", ".home", ".corp", ".test", ".example", ".invalid"];
  if (forbiddenTlds.some((tld) => normalized.endsWith(tld))) {
    return { valid: false, reason: `Private or reserved TLD in '${normalized}' is prohibited.`, hostname: normalized };
  }

  // Check IPv4 forms (decimal, octal, hex, standard dotted)
  const ipv4Num = parseIpv4ToNumber(normalized);
  if (ipv4Num !== null) {
    const check = isPrivateOrReservedIpv4(ipv4Num);
    if (check.blocked) {
      return { valid: false, reason: `Target IP is prohibited: ${check.reason}`, hostname: normalized };
    }
    return { valid: true, hostname: normalized, isIp: true };
  }

  // Check IPv6 forms
  if (normalized.includes(":") || (normalized.startsWith("[") && normalized.endsWith("]"))) {
    const check = isPrivateOrReservedIpv6(normalized);
    if (check.blocked) {
      return { valid: false, reason: `Target IPv6 is prohibited: ${check.reason}`, hostname: normalized };
    }
    return { valid: true, hostname: normalized, isIp: true };
  }

  // Domain syntax check
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(normalized)) {
    return { valid: false, reason: "Hostname contains invalid characters.", hostname: normalized };
  }

  return { valid: true, hostname: normalized, isIp: false };
}

/**
 * Sanitizes a URL for external threat intelligence lookups:
 * - Strips all basic auth credentials (user:password@)
 * - Strips fragment/hash
 * - Strips all query parameters to prevent exposing tokens, session IDs, or private data
 * - Returns target object containing sanitizedUrl, hostname, registeredDomain, and targetHash
 */
export function sanitizeUrlForThreatIntel(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    throw new Error("URL must be a non-empty string.");
  }

  const trimmed = rawUrl.trim();
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  const explicitScheme = schemeMatch ? schemeMatch[1].toLowerCase() : null;

  if (explicitScheme && explicitScheme !== "http" && explicitScheme !== "https") {
    throw new Error(`Protocol '${explicitScheme}' is not supported for external threat lookup.`);
  }

  let parseTarget = trimmed;
  if (!explicitScheme) {
    parseTarget = `http://${trimmed}`;
  }

  let parsed;
  try {
    parsed = new URL(parseTarget);
  } catch (_) {
    throw new Error("Failed to parse URL for threat inspection.");
  }

  // Host validation against SSRF
  const hostValidation = validateTargetHost(parsed.hostname);
  if (!hostValidation.valid) {
    throw new Error(hostValidation.reason);
  }

  // Construct privacy-safe representation (no auth, no query, no hash)
  const sanitizedUrl = `${parsed.protocol}//${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}${parsed.pathname || "/"}`;
  const sha256Hex = crypto.createHash("sha256").update(sanitizedUrl).digest("hex");

  return {
    originalInput: trimmed,
    sanitizedUrl,
    hostname: parsed.hostname.toLowerCase(),
    pathname: parsed.pathname || "/",
    port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
    protocol: parsed.protocol.replace(":", ""),
    sha256Hex,
  };
}

/**
 * Perform an HTTP/HTTPS JSON POST or GET with timeout and abort support.
 * Only connects to trusted threat-intel API endpoints, NEVER the user's target URL.
 */
function fetchApiWithTimeout(urlStr, options = {}, timeoutMs = 2500) {
  return new Promise((resolve, reject) => {
    const targetUrl = new URL(urlStr);
    const isHttps = targetUrl.protocol === "https:";
    const client = isHttps ? https : http;

    const reqOptions = {
      method: options.method || "GET",
      headers: options.headers || {},
      timeout: timeoutMs,
    };

    let settled = false;
    const req = client.request(targetUrl, reqOptions, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
        if (body.length > 512 * 1024) {
          // 512KB response guard
          req.destroy(new Error("Response exceeds size limit"));
        }
      });
      res.on("end", () => {
        if (settled) return;
        settled = true;
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body,
        });
      });
    });

    req.on("timeout", () => {
      req.destroy();
      if (!settled) {
        settled = true;
        const err = new Error(`Request to ${targetUrl.hostname} timed out after ${timeoutMs}ms`);
        err.code = "ETIMEDOUT";
        reject(err);
      }
    });

    req.on("error", (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });

    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

// ============================================================================
// Provider Adapters
// ============================================================================

/**
 * 1. URLhaus (Abuse.ch) Provider Adapter
 * Queries the public Abuse.ch URLhaus threat database via host lookup.
 * URLhaus tracks confirmed active malware distribution sites.
 */
export async function queryUrlhaus(hostname, timeoutMs = 2500) {
  const result = {
    provider: "urlhaus",
    providerName: "URLhaus (Abuse.ch)",
    status: "unconfigured",
    observationTime: new Date().toISOString(),
    details: null,
    reference: "https://urlhaus.abuse.ch/",
  };

  try {
    const apiKey = process.env.URLHAUS_API_KEY || process.env.URLHAUS_AUTH_KEY;
    const postData = new URLSearchParams({ host: hostname }).toString();
    const headers = {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(postData),
      "User-Agent": "CipherCheck-ThreatIntel/3.0",
    };
    if (apiKey) {
      headers["Auth-Key"] = apiKey;
    }

    const res = await fetchApiWithTimeout(
      "https://urlhaus-api.abuse.ch/v1/host/",
      {
        method: "POST",
        headers,
        body: postData,
      },
      timeoutMs
    );

    if (res.statusCode === 401) {
      result.status = "unconfigured";
      result.details = "URLhaus API requires an Abuse.ch Auth-Key (set URLHAUS_API_KEY in environment).";
      return result;
    }

    if (res.statusCode !== 200) {
      result.status = "unavailable";
      result.error = `HTTP ${res.statusCode} from URLhaus API`;
      return result;
    }

    let parsed;
    try {
      parsed = JSON.parse(res.body);
    } catch (_) {
      result.status = "error";
      result.error = "Malformed JSON from URLhaus";
      return result;
    }

    if (parsed.query_status === "ok") {
      // Host is listed in URLhaus
      const urlsCount = Array.isArray(parsed.urls) ? parsed.urls.length : 0;
      const activeUrls = Array.isArray(parsed.urls)
        ? parsed.urls.filter((u) => u.url_status === "online").length
        : 0;

      result.status = "malicious";
      result.evidence = {
        queryStatus: parsed.query_status,
        threat: "malware_distribution",
        firstSeen: parsed.firstseen,
        totalUrlsFound: urlsCount,
        activeMalwareUrls: activeUrls,
        urlhausReference: parsed.urlhaus_reference || `https://urlhaus.abuse.ch/host/${encodeURIComponent(hostname)}/`,
      };
      result.reference = result.evidence.urlhausReference;
      result.details = `Host listed in URLhaus with ${urlsCount} recorded malware URL(s) (${activeUrls} active).`;
      return result;
    }

    if (parsed.query_status === "no_results") {
      result.status = "no_match";
      result.details = "No recorded malware campaigns found in URLhaus database.";
      return result;
    }

    result.status = "no_match";
    result.details = `Query status: ${parsed.query_status || "unknown"}`;
    return result;
  } catch (err) {
    if (err.code === "ETIMEDOUT") {
      result.status = "timeout";
      result.error = "URLhaus query timed out";
    } else {
      result.status = "unavailable";
      result.error = err.message || "Failed to reach URLhaus";
    }
    return result;
  }
}

/**
 * 2. Cloudflare 1.1.1.2 Security DoH Provider Adapter
 * Queries Cloudflare's Malware-Blocking DNS service via DNS-over-HTTPS.
 * When a domain is flagged as malware/phishing by Cloudflare, 1.1.1.2 returns
 * 0.0.0.0 or blocked status instead of the genuine IP.
 */
export async function queryCloudflareSecurityDns(hostname, timeoutMs = 2500) {
  const result = {
    provider: "cloudflare_security_dns",
    providerName: "Cloudflare 1.1.1.2 Security DNS",
    status: "unconfigured",
    observationTime: new Date().toISOString(),
    details: null,
    reference: "https://developers.cloudflare.com/1.1.1.1/setup/#1111-for-families",
  };

  try {
    const url = `https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`;
    const res = await fetchApiWithTimeout(
      url,
      {
        method: "GET",
        headers: {
          Accept: "application/dns-json",
          "User-Agent": "CipherCheck-ThreatIntel/3.0",
        },
      },
      timeoutMs
    );

    if (res.statusCode !== 200) {
      result.status = "unavailable";
      result.error = `HTTP ${res.statusCode} from Cloudflare DNS`;
      return result;
    }

    let parsed;
    try {
      parsed = JSON.parse(res.body);
    } catch (_) {
      result.status = "error";
      result.error = "Malformed JSON from DNS query";
      return result;
    }

    // Cloudflare returns Status 0 (NOERROR) for valid domains.
    // If blocked for malware, Answer section contains 0.0.0.0
    const answers = Array.isArray(parsed.Answer) ? parsed.Answer : [];
    const isBlockedIp = answers.some((a) => a.data === "0.0.0.0");

    if (isBlockedIp) {
      result.status = "malicious";
      result.evidence = {
        dnsStatus: parsed.Status,
        resolvedAnswers: answers,
        threat: "security_policy_block",
        details: "Domain resolved to 0.0.0.0 under Cloudflare Malware Protection policy.",
      };
      result.details = "Blocked by Cloudflare Security DNS filter for malware or threat activity.";
      return result;
    }

    if (parsed.Status === 3) {
      // NXDOMAIN
      result.status = "no_match";
      result.details = "Domain does not resolve (NXDOMAIN) under Security DNS.";
      return result;
    }

    if (parsed.Status === 0) {
      result.status = "no_match";
      result.details = "Domain resolved normally without security policy intervention.";
      return result;
    }

    result.status = "no_match";
    result.details = `DNS query returned status code ${parsed.Status}.`;
    return result;
  } catch (err) {
    if (err.code === "ETIMEDOUT") {
      result.status = "timeout";
      result.error = "Cloudflare Security DNS query timed out";
    } else {
      result.status = "unavailable";
      result.error = err.message || "Failed to reach Cloudflare DNS";
    }
    return result;
  }
}

/**
 * 3. Google Safe Browsing v4 Adapter
 * Queries Google Safe Browsing Lookup API if GOOGLE_SAFE_BROWSING_KEY is set.
 */
export async function queryGoogleSafeBrowsing(sanitizedUrl, timeoutMs = 2500) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY || process.env.SAFE_BROWSING_API_KEY;
  const result = {
    provider: "google_safe_browsing",
    providerName: "Google Safe Browsing",
    status: apiKey ? "no_match" : "unconfigured",
    observationTime: new Date().toISOString(),
    details: null,
    reference: "https://developers.google.com/safe-browsing",
  };

  if (!apiKey) {
    result.status = "unconfigured";
    result.details = "Google Safe Browsing API key not set in environment (GOOGLE_SAFE_BROWSING_KEY).";
    return result;
  }

  try {
    const postPayload = JSON.stringify({
      client: {
        clientId: "ciphercheck-3000",
        clientVersion: "3.0.0",
      },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION",
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: sanitizedUrl }],
      },
    });

    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;
    const res = await fetchApiWithTimeout(
      apiUrl,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(postPayload),
        },
        body: postPayload,
      },
      timeoutMs
    );

    if (res.statusCode !== 200) {
      result.status = "unavailable";
      result.error = `HTTP ${res.statusCode} from Safe Browsing API`;
      return result;
    }

    const data = JSON.parse(res.body);
    if (data && Array.isArray(data.matches) && data.matches.length > 0) {
      const match = data.matches[0];
      result.status = "malicious";
      result.evidence = {
        threatType: match.threatType,
        platformType: match.platformType,
        threatEntryType: match.threatEntryType,
      };
      result.details = `Identified as ${match.threatType} by Google Safe Browsing.`;
      return result;
    }

    result.status = "no_match";
    result.details = "No threats flagged in Google Safe Browsing lists.";
    return result;
  } catch (err) {
    if (err.code === "ETIMEDOUT") {
      result.status = "timeout";
      result.error = "Safe Browsing request timed out";
    } else {
      result.status = "unavailable";
      result.error = err.message || "Safe Browsing query failed";
    }
    return result;
  }
}

/**
 * 4. VirusTotal v3 Adapter
 * Queries VirusTotal v3 URL analysis if VIRUSTOTAL_API_KEY is configured.
 */
export async function queryVirusTotal(sanitizedUrl, timeoutMs = 2500) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  const result = {
    provider: "virustotal",
    providerName: "VirusTotal v3",
    status: apiKey ? "no_match" : "unconfigured",
    observationTime: new Date().toISOString(),
    details: null,
    reference: "https://www.virustotal.com/",
  };

  if (!apiKey) {
    result.status = "unconfigured";
    result.details = "VirusTotal API key not configured (VIRUSTOTAL_API_KEY).";
    return result;
  }

  try {
    // VirusTotal URL ID format: base64 without padding of sha256 or url
    const urlId = Buffer.from(sanitizedUrl).toString("base64").replace(/=+$/, "");
    const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;

    const res = await fetchApiWithTimeout(
      apiUrl,
      {
        method: "GET",
        headers: {
          "x-apikey": apiKey,
          Accept: "application/json",
          "User-Agent": "CipherCheck-ThreatIntel/3.0",
        },
      },
      timeoutMs
    );

    if (res.statusCode === 404) {
      result.status = "no_match";
      result.details = "URL not currently indexed in VirusTotal scan cache.";
      return result;
    }

    if (res.statusCode === 429) {
      result.status = "unavailable";
      result.error = "VirusTotal rate limit exceeded (4 req/min free tier).";
      return result;
    }

    if (res.statusCode !== 200) {
      result.status = "unavailable";
      result.error = `HTTP ${res.statusCode} from VirusTotal API`;
      return result;
    }

    const data = JSON.parse(res.body);
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (stats) {
      const maliciousCount = Number(stats.malicious || 0);
      const suspiciousCount = Number(stats.suspicious || 0);

      if (maliciousCount >= 1 || suspiciousCount >= 2) {
        result.status = "malicious";
        result.evidence = {
          maliciousEngines: maliciousCount,
          suspiciousEngines: suspiciousCount,
          harmlessEngines: Number(stats.harmless || 0),
          undetectedEngines: Number(stats.undetected || 0),
          lastAnalysisDate: data?.data?.attributes?.last_analysis_date,
        };
        result.details = `Flagged by ${maliciousCount} security vendor(s) on VirusTotal.`;
        return result;
      }

      result.status = "no_match";
      result.details = `Scanned by ${stats.harmless || 0} engines with 0 malicious detections.`;
      return result;
    }

    result.status = "no_match";
    result.details = "No vendor detection data available.";
    return result;
  } catch (err) {
    if (err.code === "ETIMEDOUT") {
      result.status = "timeout";
      result.error = "VirusTotal request timed out";
    } else {
      result.status = "unavailable";
      result.error = err.message || "VirusTotal query failed";
    }
    return result;
  }
}

// ============================================================================
// Multi-Provider Orchestrator & Verdict Engine
// ============================================================================

/**
 * Classifies the assessment according to the 4 strict outcome categories:
 * 1. Confirmed Threat
 * 2. Suspicious / Heuristic Warning
 * 3. Unverified / Insufficient Data
 * 4. No Obvious Indicators
 */
export function classifyAssessment(heuristicVerdictLevel, heuristicFindings = [], threatIntelResults = {}) {
  const providers = threatIntelResults.providers || {};
  const providerList = Object.values(providers);

  const maliciousProviders = providerList.filter((p) => p.status === "malicious");
  const hasConfirmedMalice = maliciousProviders.length > 0;

  const hasHighHeuristic =
    heuristicVerdictLevel === "high" ||
    heuristicFindings.some((f) => f.severity === "high");

  const hasSuspiciousHeuristic =
    heuristicVerdictLevel === "medium" ||
    heuristicVerdictLevel === "suspicious" ||
    heuristicFindings.some((f) => f.severity === "suspicious" || f.severity === "warning");

  const responsiveProviders = providerList.filter(
    (p) => p.status === "no_match" || p.status === "malicious"
  );

  // 1. Confirmed Threat
  if (hasConfirmedMalice) {
    const providerNames = maliciousProviders.map((p) => p.providerName).join(", ");
    return {
      category: "Confirmed Threat",
      categoryKey: "confirmed-threat",
      badgeLevel: "high",
      title: "Confirmed Malicious Destination",
      summary: `Active threat flagged by verified intelligence source(s): ${providerNames}. Immediate risk of credentials theft or malware delivery.`,
      confidence: "High (Verified Threat Intelligence)",
      limitations: "Intelligence indicates active threat records. Do not navigate to or submit credentials on this address.",
    };
  }

  // 2. Suspicious / Heuristic Warning
  if (hasHighHeuristic || hasSuspiciousHeuristic) {
    return {
      category: "Suspicious / Heuristic Warning",
      categoryKey: "suspicious-warning",
      badgeLevel: hasHighHeuristic ? "high" : "medium",
      title: hasHighHeuristic ? "High-Risk Structural Deception" : "Elevated Caution / Heuristic Warnings",
      summary: hasHighHeuristic
        ? "Deceptive structural patterns or evasion indicators detected. While not yet listed on active threat feeds, this link exhibits high-risk properties."
        : "Structural anomalies or non-standard patterns detected that warrant caution before interacting.",
      confidence: "Moderate (Static Structural Analysis)",
      limitations: "Evaluated using structural pattern heuristics. No threat feed matches were found, but absence of blocklist entries does not prove legitimacy.",
    };
  }

  // 3. Unverified / Insufficient Data (clean heuristics, but 0 threat intelligence providers responded or all unconfigured)
  if (responsiveProviders.length === 0) {
    return {
      category: "Unverified / Insufficient Data",
      categoryKey: "unverified",
      badgeLevel: "low",
      title: "Unverified Destination (Insufficient Threat Data)",
      summary: "No structural red flags detected locally, but external threat intelligence providers were unavailable or unconfigured.",
      confidence: "Limited (Structural Heuristics Only)",
      limitations: "Threat intelligence feeds were unavailable. This URL has not been corroborated against live reputation databases.",
    };
  }

  // 4. No Obvious Indicators (clean heuristics AND responsive providers reported no match)
  return {
    category: "No Obvious Indicators",
    categoryKey: "no-indicators",
    badgeLevel: "clean",
    title: "No Obvious Indicators Detected",
    summary: "No structural anomalies detected and no active threat listings found across queried intelligence databases.",
    confidence: "Standard (Heuristics & Clean Intelligence Feeds)",
    limitations: "Absence of detected indicators does NOT establish that a website is free of zero-day phishing or newly deployed malware. Always verify destination identity before logging in.",
  };
}

/**
 * Orchestrates multi-provider threat intelligence inspection for a sanitized target URL.
 * Handles cache hits, parallel adapter execution, timeout isolation, and verdict classification.
 */
export async function inspectUrlTarget(rawUrl, options = {}) {
  pruneCache();

  // 1. Sanitize input & validate against SSRF
  const target = sanitizeUrlForThreatIntel(rawUrl);

  // 2. Check in-memory cache
  const cacheKey = `intel:${target.hostname}:${target.sha256Hex}`;
  const now = Date.now();
  const cached = THREAT_CACHE.get(cacheKey);
  if (cached && cached.expiresAt > now) {
    return {
      ...cached.data,
      fromCache: true,
      cachedAt: cached.cachedAt,
    };
  }

  const timeoutMs = typeof options.timeoutMs === "number" ? options.timeoutMs : 2500;

  // 3. Query providers in parallel
  const [urlhausRes, cloudflareRes, safeBrowsingRes, virusTotalRes] = await Promise.all([
    queryUrlhaus(target.hostname, timeoutMs),
    queryCloudflareSecurityDns(target.hostname, timeoutMs),
    queryGoogleSafeBrowsing(target.sanitizedUrl, timeoutMs),
    queryVirusTotal(target.sanitizedUrl, timeoutMs),
  ]);

  const providers = {
    urlhaus: urlhausRes,
    cloudflareDns: cloudflareRes,
    safeBrowsing: safeBrowsingRes,
    virusTotal: virusTotalRes,
  };

  const maliciousCount = Object.values(providers).filter((p) => p.status === "malicious").length;
  const queriedCount = Object.values(providers).filter(
    (p) => p.status !== "unconfigured"
  ).length;

  const resultData = {
    target: {
      hostname: target.hostname,
      protocol: target.protocol,
      port: target.port,
      sanitizedUrl: target.sanitizedUrl,
      sha256Hex: target.sha256Hex,
    },
    inspectionTime: new Date().toISOString(),
    fromCache: false,
    providers,
    summary: {
      queriedProviders: queriedCount,
      maliciousMatches: maliciousCount,
      hasConfirmedThreat: maliciousCount > 0,
    },
  };

  // 4. Cache results (longer TTL for malicious findings)
  const ttl = maliciousCount > 0 ? MALICIOUS_CACHE_TTL_MS : DEFAULT_CACHE_TTL_MS;
  THREAT_CACHE.set(cacheKey, {
    data: resultData,
    cachedAt: new Date().toISOString(),
    expiresAt: now + ttl,
  });

  return resultData;
}

/**
 * Clear in-memory cache (useful for test suites)
 */
export function clearThreatCache() {
  THREAT_CACHE.clear();
  rateLimitBuckets.clear();
}
