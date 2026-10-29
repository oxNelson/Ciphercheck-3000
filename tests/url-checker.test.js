import { test, describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load functions from ciphercheck/script.js into a test sandbox
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
    `\nvar __exported = { analyzeUrl, extractDomainParts, formatUrlReport }; __exported;`,
  sandbox
);

const { analyzeUrl, extractDomainParts, formatUrlReport } = exported;

describe("CipherCheck URL & Link Risk Checker", () => {
  test("Rejects empty or whitespace-only inputs with helpful errors", () => {
    const empty = analyzeUrl("");
    assert.equal(empty.isValid, false);
    assert.match(empty.error, /enter a URL/i);

    const whitespace = analyzeUrl("   ");
    assert.equal(whitespace.isValid, false);
    assert.match(whitespace.error, /enter a URL/i);

    const nonString = analyzeUrl(null);
    assert.equal(nonString.isValid, false);
  });

  test("Gracefully handles and rejects malformed unparseable URLs", () => {
    const broken = analyzeUrl("https://");
    assert.equal(broken.isValid, false);
    assert.match(broken.error, /valid URL structure/i);
  });

  test("Infers scheme when URL is entered without protocol prefix", () => {
    const res = analyzeUrl("github.com/torvalds/linux");
    assert.equal(res.isValid, true);
    assert.equal(res.urlParts.hostname, "github.com");
    assert.equal(res.urlParts.pathname, "/torvalds/linux");
    assert.ok(res.facts.some((f) => f.label.includes("Protocol") && f.value.includes("inferred")));
  });

  test("HTTPS clean URLs receive No Obvious Red Flags verdict without claiming absolute safety", () => {
    const res = analyzeUrl("https://github.com/torvalds/linux");
    assert.equal(res.isValid, true);
    assert.equal(res.verdict.level, "clean");
    assert.equal(res.verdict.title, "No Obvious Red Flags Detected");
    assert.equal(res.findings.length, 0);

    // Disclaimers must emphasize that clean does not equal guaranteed safe
    assert.ok(
      res.disclaimers.some((d) =>
        d.includes("absence of detected indicators does NOT establish that a website is free of malware")
      )
    );
    assert.ok(
      res.disclaimers.some((d) =>
        d.includes("HTTPS provides encrypted transit between your browser and the server, but does NOT guarantee")
      )
    );
  });

  test("Detects unencrypted HTTP protocol as a warning finding", () => {
    const res = analyzeUrl("http://example.com/login");
    assert.equal(res.isValid, true);
    const httpFinding = res.findings.find((f) => f.id === "unencrypted-http");
    assert.ok(httpFinding);
    assert.equal(httpFinding.severity, "warning");
    assert.match(httpFinding.whyItMatters, /transmitted in cleartext/i);
    assert.notEqual(res.verdict.level, "clean");
  });

  test("Detects raw IPv4 address used as host", () => {
    const res = analyzeUrl("http://192.168.1.50/admin");
    assert.equal(res.isValid, true);
    const ipFinding = res.findings.find((f) => f.id === "raw-ip-host");
    assert.ok(ipFinding);
    assert.equal(ipFinding.severity, "suspicious");
    assert.match(ipFinding.whyItMatters, /bypass domain-based reputation/i);
  });

  test("Detects raw IPv6 bracketed address used as host", () => {
    const res = analyzeUrl("http://[2001:db8::1]:8080/status");
    assert.equal(res.isValid, true);
    const ipFinding = res.findings.find((f) => f.id === "raw-ip-host");
    assert.ok(ipFinding);
    assert.equal(ipFinding.severity, "suspicious");
  });

  test("Detects deceptive embedded authority (@ symbol credential trick)", () => {
    const res = analyzeUrl("https://paypal.com:verify@evil-attacker.com/signin");
    assert.equal(res.isValid, true);
    const credFinding = res.findings.find((f) => f.id === "embedded-credentials");
    assert.ok(credFinding);
    assert.equal(credFinding.severity, "high");
    assert.equal(res.verdict.level, "high");
    assert.match(credFinding.explanation, /connects to 'evil-attacker.com'/);
  });

  test("Detects Punycode (IDN) domains commonly used in homoglyph attacks", () => {
    const res = analyzeUrl("https://xn--pple-43d.com/support");
    assert.equal(res.isValid, true);
    const punyFinding = res.findings.find((f) => f.id === "punycode-domain");
    assert.ok(punyFinding);
    assert.equal(punyFinding.severity, "warning");
    assert.match(punyFinding.whyItMatters, /homoglyph attacks/i);
  });

  test("Detects invisible, zero-width, or control characters as high risk", () => {
    const res = analyzeUrl("https://legit-site.com\u200B/phishing");
    assert.equal(res.isValid, true);
    const hiddenFinding = res.findings.find((f) => f.id === "hidden-characters");
    assert.ok(hiddenFinding);
    assert.equal(hiddenFinding.severity, "high");
    assert.equal(res.verdict.level, "high");
  });

  test("Detects excessive subdomain nesting used to disguise destination", () => {
    const res = analyzeUrl("https://secure.login.banking.portal.legit-look.net/auth");
    assert.equal(res.isValid, true);
    const subFinding = res.findings.find((f) => f.id === "excessive-subdomains");
    assert.ok(subFinding);
    assert.equal(subFinding.severity, "warning");
  });

  test("Detects brand impersonation in unauthorized domains", () => {
    const res = analyzeUrl("https://paypal-account-security-alert.com/login");
    assert.equal(res.isValid, true);
    const brandFinding = res.findings.find((f) => f.id === "brand-impersonation-paypal");
    assert.ok(brandFinding);
    assert.equal(brandFinding.severity, "suspicious");
    assert.match(brandFinding.title, /PayPal/);
  });

  test("Avoids false-positive brand impersonation on official domains", () => {
    const officialPaypal = analyzeUrl("https://www.paypal.com/signin");
    assert.equal(officialPaypal.isValid, true);
    assert.equal(officialPaypal.findings.some((f) => f.id.startsWith("brand-impersonation")), false);

    const officialGoogleUk = analyzeUrl("https://www.google.co.uk/search?q=test");
    assert.equal(officialGoogleUk.isValid, true);
    assert.equal(officialGoogleUk.findings.some((f) => f.id.startsWith("brand-impersonation")), false);

    const officialApple = analyzeUrl("https://appleid.apple.com/");
    assert.equal(officialApple.isValid, true);
    assert.equal(officialApple.findings.some((f) => f.id.startsWith("brand-impersonation")), false);
  });

  test("Detects high-abuse or file-extension top-level domains", () => {
    const res = analyzeUrl("https://system-update.zip/download");
    assert.equal(res.isValid, true);
    const tldFinding = res.findings.find((f) => f.id === "suspicious-tld");
    assert.ok(tldFinding);
    assert.equal(tldFinding.severity, "notice");
    assert.match(tldFinding.title, /\.zip/);
  });

  test("Detects non-standard web ports", () => {
    const res = analyzeUrl("https://example.com:8443/api");
    assert.equal(res.isValid, true);
    const portFinding = res.findings.find((f) => f.id === "non-standard-port");
    assert.ok(portFinding);
    assert.equal(portFinding.severity, "warning");
    assert.match(portFinding.title, /:8443/);
  });

  test("Detects suspicious percent-encoding obfuscation", () => {
    const res = analyzeUrl("https://example.com/%2e%2e/%2fetc/passwd");
    assert.equal(res.isValid, true);
    const encFinding = res.findings.find((f) => f.id === "suspicious-encoding");
    assert.ok(encFinding);
    assert.equal(encFinding.severity, "warning");
  });

  test("Detects dangerous pseudo-protocols like javascript: and data: as high risk", () => {
    const jsUri = analyzeUrl("javascript:alert(document.cookie)");
    assert.equal(jsUri.isValid, true);
    const jsFinding = jsUri.findings.find((f) => f.id === "dangerous-protocol");
    assert.ok(jsFinding);
    assert.equal(jsFinding.severity, "high");
    assert.equal(jsUri.verdict.level, "high");

    const dataUri = analyzeUrl("data:text/html,<script>evil()</script>");
    assert.equal(dataUri.isValid, true);
    const dataFinding = dataUri.findings.find((f) => f.id === "dangerous-protocol");
    assert.ok(dataFinding);
    assert.equal(dataFinding.severity, "high");
  });

  test("extractDomainParts correctly splits standard and two-level ccTLDs", () => {
    const standard = extractDomainParts("sub.example.com");
    assert.equal(standard.registeredDomain, "example.com");
    assert.equal(standard.subdomain, "sub");

    const ukDomain = extractDomainParts("login.service.gov.uk");
    assert.equal(ukDomain.registeredDomain, "service.gov.uk");
    assert.equal(ukDomain.subdomain, "login");

    const auDomain = extractDomainParts("portal.chase.com.au");
    assert.equal(auDomain.registeredDomain, "chase.com.au");
    assert.equal(auDomain.subdomain, "portal");
  });

  test("formatUrlReport formats complete copyable report with all sections", () => {
    const analysis = analyzeUrl("https://paypal.com.account-verify.attacker.xyz/login");
    const report = formatUrlReport(analysis);

    assert.ok(report.includes("CIPHERCHECK — LINK & URL RISK ANALYSIS REPORT"));
    assert.ok(report.includes("Target URL:"));
    assert.ok(report.includes("VERDICT:"));
    assert.ok(report.includes("OBSERVED STRUCTURAL FACTS:"));
    assert.ok(report.includes("DETECTED STRUCTURAL INDICATORS"));
    assert.ok(report.includes("DISCLAIMERS & HEURISTIC LIMITATIONS:"));
    assert.ok(report.includes("Local Static Structural Heuristic"));
  });

  // =========================================================================
  // AUDIT REGRESSION TESTS: False Positives, Brand Tokenization, & Deceptions
  // =========================================================================

  test("Regression: Avoids false positives on legitimate words containing brand substrings", () => {
    // 'apple' inside pineapple, snapple
    const pineapple = analyzeUrl("https://www.pineapple.com/recipes");
    assert.equal(pineapple.isValid, true);
    assert.equal(pineapple.findings.some((f) => f.id.startsWith("brand-impersonation")), false);

    const snapple = analyzeUrl("https://snapple.com/drinks");
    assert.equal(snapple.isValid, true);
    assert.equal(snapple.findings.some((f) => f.id.startsWith("brand-impersonation")), false);

    // 'chase' inside purchase, chasethedream
    const purchase = analyzeUrl("https://purchase.com/checkout");
    assert.equal(purchase.isValid, true);
    assert.equal(purchase.findings.some((f) => f.id.startsWith("brand-impersonation")), false);

    const chasethedream = analyzeUrl("https://chasethedream.com/about");
    assert.equal(chasethedream.isValid, true);
    assert.equal(chasethedream.findings.some((f) => f.id.startsWith("brand-impersonation")), false);

    // 'steam' inside steamboatsprings, mainstreammedia
    const steamboat = analyzeUrl("https://steamboatsprings.gov/city");
    assert.equal(steamboat.isValid, true);
    assert.equal(steamboat.findings.some((f) => f.id.startsWith("brand-impersonation")), false);

    const mainstream = analyzeUrl("https://mainstreammedia.com/articles");
    assert.equal(mainstream.isValid, true);
    assert.equal(mainstream.findings.some((f) => f.id.startsWith("brand-impersonation")), false);

    // 'amazon' inside amazonia
    const amazonia = analyzeUrl("https://amazonia.org/conservation");
    assert.equal(amazonia.isValid, true);
    assert.equal(amazonia.findings.some((f) => f.id.startsWith("brand-impersonation")), false);
  });

  test("Regression: Accurately detects brand impersonation across subdomains, compound words, and leetspeak", () => {
    // Subdomain brand impersonation
    const subBrand = analyzeUrl("https://apple.account-update.net/auth");
    assert.equal(subBrand.isValid, true);
    const appleSubFinding = subBrand.findings.find((f) => f.id === "brand-impersonation-apple");
    assert.ok(appleSubFinding);
    assert.match(appleSubFinding.explanation, /appears in subdomain/i);

    // Compound word with phishing modifier (paypallogin)
    const compound = analyzeUrl("https://paypallogin.org/submit");
    assert.equal(compound.isValid, true);
    const paypalFinding = compound.findings.find((f) => f.id === "brand-impersonation-paypal");
    assert.ok(paypalFinding);

    // Compound word with security modifier (chaseonline)
    const chaseOnline = analyzeUrl("https://chaseonline-banking.net/");
    assert.equal(chaseOnline.isValid, true);
    const chaseFinding = chaseOnline.findings.find((f) => f.id === "brand-impersonation-chase");
    assert.ok(chaseFinding);

    // Typosquatting / leetspeak (paypa1, g00gle)
    const leetPaypal = analyzeUrl("https://paypa1-security.com/");
    assert.equal(leetPaypal.isValid, true);
    const leetFinding = leetPaypal.findings.find((f) => f.id === "brand-impersonation-paypal");
    assert.ok(leetFinding);
    assert.match(leetFinding.title, /Typosquatting/i);

    const leetGoogle = analyzeUrl("https://g00gle-login.com/");
    assert.equal(leetGoogle.isValid, true);
    const googleFinding = leetGoogle.findings.find((f) => f.id === "brand-impersonation-google");
    assert.ok(googleFinding);
  });

  test("Regression: Detects deceptive TLD embedded inside subdomain hierarchy", () => {
    const deceptiveSub = analyzeUrl("https://paypal.com.account-verification.net/signin");
    assert.equal(deceptiveSub.isValid, true);
    const tldSubFinding = deceptiveSub.findings.find((f) => f.id === "embedded-tld-subdomain");
    assert.ok(tldSubFinding);
    assert.equal(tldSubFinding.severity, "suspicious");
    assert.match(tldSubFinding.explanation, /contains a top-level domain label/i);
  });

  test("Regression: Correctly parses registered domain with trailing FQDN dot and international ccTLDs", () => {
    // Trailing FQDN dot normalized cleanly
    const dotDomain = extractDomainParts("example.com.");
    assert.equal(dotDomain.registeredDomain, "example.com");
    assert.equal(dotDomain.subdomain, "");

    // Hong Kong (.gov.hk)
    const hkDomain = extractDomainParts("portal.service.gov.hk");
    assert.equal(hkDomain.registeredDomain, "service.gov.hk");
    assert.equal(hkDomain.subdomain, "portal");

    // South Korea (.co.kr)
    const krDomain = extractDomainParts("api.naver.co.kr");
    assert.equal(krDomain.registeredDomain, "naver.co.kr");
    assert.equal(krDomain.subdomain, "api");

    // Malaysia (.com.my)
    const myDomain = extractDomainParts("mall.shopee.com.my");
    assert.equal(myDomain.registeredDomain, "shopee.com.my");
    assert.equal(myDomain.subdomain, "mall");
  });

  test("Regression: Findings and disclaimers strictly distinguish observable indicators from confirmed malice", () => {
    const res = analyzeUrl("https://paypal-update.net/auth");
    assert.equal(res.isValid, true);

    // Verify findings use observable language rather than claiming confirmed malicious state
    for (const f of res.findings) {
      assert.ok(f.explanation.includes("Observable indicator") || f.whyItMatters);
      assert.doesNotMatch(f.explanation, /confirmed malware/i);
      assert.doesNotMatch(f.explanation, /confirmed phishing attack/i);
    }

    // Verify disclaimers explicitly clarify local static heuristics without live scanning
    assert.ok(res.disclaimers.some((d) => d.includes("does not query live threat-intelligence APIs")));
    assert.ok(res.disclaimers.some((d) => d.includes("without fetching external servers")));
  });

  // =========================================================================
  // FINAL VALIDATION REGRESSION TESTS: Authority Tricks, Query Encoding, Path @
  // =========================================================================

  test("Final Validation: Wikipedia and paths containing brand names are not flagged as impersonation", () => {
    const wiki = analyzeUrl("https://www.wikipedia.org");
    assert.equal(wiki.isValid, true);
    assert.equal(wiki.verdict.level, "clean");
    assert.equal(wiki.findings.length, 0);

    const wikiApple = analyzeUrl("https://www.wikipedia.org/wiki/Apple_Inc.");
    assert.equal(wikiApple.isValid, true);
    assert.equal(wikiApple.verdict.level, "clean");
    assert.equal(wikiApple.findings.some((f) => f.id.startsWith("brand-impersonation")), false);
  });

  test("Final Validation: True authority @ tricks are flagged, but @ in paths and queries are not", () => {
    // True authority trick
    const trick = analyzeUrl("https://apple.com:password@phishing-hub.com/login");
    assert.equal(trick.isValid, true);
    assert.ok(trick.findings.some((f) => f.id === "embedded-credentials"));
    assert.equal(trick.verdict.level, "high");

    // Social media / path @ handle
    const yt = analyzeUrl("https://www.youtube.com/@veritasium");
    assert.equal(yt.isValid, true);
    assert.equal(yt.findings.some((f) => f.id === "embedded-credentials"), false);

    const medium = analyzeUrl("https://medium.com/@author/how-to-code");
    assert.equal(medium.isValid, true);
    assert.equal(medium.findings.some((f) => f.id === "embedded-credentials"), false);

    // Email in query parameter
    const queryEmail = analyzeUrl("https://example.com/search?user=admin@company.com");
    assert.equal(queryEmail.isValid, true);
    assert.equal(queryEmail.findings.some((f) => f.id === "embedded-credentials"), false);
  });

  test("Final Validation: Percent-encoding checks catch path traversal and null bytes without false-positive queries", () => {
    // Legitimate query encoding
    const searchPercent = analyzeUrl("https://www.google.com/search?q=50%25+off");
    assert.equal(searchPercent.isValid, true);
    assert.equal(searchPercent.findings.some((f) => f.id === "suspicious-encoding"), false);

    const oauth = analyzeUrl("https://example.com/oauth?redirect_uri=https%3A%2F%2Fapp.com%2Fcallback");
    assert.equal(oauth.isValid, true);
    assert.equal(oauth.findings.some((f) => f.id === "suspicious-encoding"), false);

    // True path traversal attacks
    const pathTraversal = analyzeUrl("https://example.com/..%2f..%2fetc/passwd");
    assert.equal(pathTraversal.isValid, true);
    assert.ok(pathTraversal.findings.some((f) => f.id === "suspicious-encoding"));

    const queryTraversal = analyzeUrl("https://example.com/view?file=..%2fetc/passwd");
    assert.equal(queryTraversal.isValid, true);
    assert.ok(queryTraversal.findings.some((f) => f.id === "suspicious-encoding"));

    // Null byte injection
    const nullByte = analyzeUrl("https://example.com/file%00.jpg");
    assert.equal(nullByte.isValid, true);
    assert.ok(nullByte.findings.some((f) => f.id === "suspicious-encoding"));
    assert.equal(nullByte.verdict.level, "high");
  });

  test("Final Validation: Brand impersonation in deceptive subdomain with embedded TLD", () => {
    const res = analyzeUrl("https://apple.com.evil-site.net/auth");
    assert.equal(res.isValid, true);
    assert.ok(res.findings.some((f) => f.id === "brand-impersonation-apple"));
    assert.ok(res.findings.some((f) => f.id === "embedded-tld-subdomain"));
    assert.equal(res.urlParts.registeredDomain, "evil-site.net");
    assert.equal(res.urlParts.subdomain, "apple.com");
  });
});
