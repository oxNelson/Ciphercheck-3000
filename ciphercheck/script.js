"use strict";

const COMMON_WORDS = [
  "password",
  "admin",
  "welcome",
  "letmein",
  "qwerty",
  "iloveyou",
  "monkey",
  "dragon",
  "football",
  "secret",
  "login",
  "princess",
  "sunshine",
  "master",
  "trustno1",
  "abc123",
  "changeme",
  "default",
  "root",
];

const KEYBOARD_SEQUENCES = ["qwerty", "asdfgh", "zxcvbn"];

const STRENGTH_BANDS = [
  { min: 0, max: 19, name: "Very Weak", key: "very-weak" },
  { min: 20, max: 39, name: "Weak", key: "weak" },
  { min: 40, max: 64, name: "Fair", key: "fair" },
  { min: 65, max: 84, name: "Strong", key: "strong" },
  { min: 85, max: 100, name: "Very Strong", key: "very-strong" },
];

const PATTERN_PENALTIES = {
  sequence: 25,
  common: 25,
  repetition: 22,
  repeatedSequence: 18,
  construction: 15,
};

const CHARACTER_POOLS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{}:,.?",
};

function getStrengthBand(score) {
  return STRENGTH_BANDS.find((band) => score >= band.min && score <= band.max);
}

function lengthPoints(length) {
  if (length < 6) return 0;
  if (length < 8) return 6;
  if (length < 12) return 12;
  if (length < 16) return 27;
  if (length < 20) return 35;
  return 40;
}

function hasCharacter(password, expression) {
  return expression.test(password);
}

function hasSequentialRun(password) {
  let ascending = 1;
  let descending = 1;
  const normalized = password.toLowerCase();

  for (let index = 1; index < normalized.length; index += 1) {
    const previous = normalized.charCodeAt(index - 1);
    const current = normalized.charCodeAt(index);
    const isAsciiAlphaNumeric =
      (current >= 48 && current <= 57) ||
      (current >= 97 && current <= 122);
    const previousIsAsciiAlphaNumeric =
      (previous >= 48 && previous <= 57) ||
      (previous >= 97 && previous <= 122);

    if (!isAsciiAlphaNumeric || !previousIsAsciiAlphaNumeric) {
      ascending = 1;
      descending = 1;
      continue;
    }

    ascending = current === previous + 1 ? ascending + 1 : 1;
    descending = current === previous - 1 ? descending + 1 : 1;

    if (ascending >= 3 || descending >= 3) return true;
  }

  return false;
}

function hasRepeatedCharacterRun(password) {
  return /(.)\1{3,}/su.test(password);
}

function hasRepeatedSequence(password) {
  const normalized = password.toLowerCase();

  for (
    let sequenceLength = 2;
    sequenceLength <= Math.min(8, Math.floor(normalized.length / 2));
    sequenceLength += 1
  ) {
    for (
      let start = 0;
      start <= normalized.length - sequenceLength * 2;
      start += 1
    ) {
      const sequence = normalized.slice(start, start + sequenceLength);
      const repeated = normalized.slice(
        start + sequenceLength,
        start + sequenceLength * 2,
      );

      if (sequence === repeated && new Set(sequence).size > 1) return true;
    }
  }

  return false;
}

function normalizeForWordChecks(password) {
  return password.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function hasCommonWord(normalized) {
  return COMMON_WORDS.some((word) => normalized.includes(word));
}

function hasKeyboardPattern(normalized) {
  return KEYBOARD_SEQUENCES.some(
    (sequence) =>
      normalized.includes(sequence) ||
      normalized.includes([...sequence].reverse().join("")),
  );
}

function hasSimpleConstruction(normalized) {
  return /^[a-z]{3,}\d{1,6}$/.test(normalized);
}

function analyzePassword(password) {
  const value = String(password);
  const length = [...value].length;
  const categories = {
    uppercase: hasCharacter(value, /[A-Z]/),
    lowercase: hasCharacter(value, /[a-z]/),
    numbers: hasCharacter(value, /\d/),
    symbols: hasCharacter(value, /[^A-Za-z0-9]/),
  };
  const categoryCount = Object.values(categories).filter(Boolean).length;
  const uniqueCount = new Set([...value]).size;
  const uniquePoints =
    length === 0 ? 0 : Math.round((uniqueCount / length) * 15);
  const normalized = normalizeForWordChecks(value);
  const findings = [];

  if (hasSequentialRun(value)) {
    findings.push({
      id: "sequence",
      title: "Predictable sequence",
      explanation:
        "Three or more consecutive letters or digits appear in ascending or descending order.",
      recommendation:
        "Replace the run with unrelated characters rather than shifting or extending the sequence.",
    });
  }

  if (hasCommonWord(normalized) || hasKeyboardPattern(normalized)) {
    findings.push({
      id: "common",
      title: "Common password pattern",
      explanation:
        "The password contains a word from CipherCheck’s documented common-pattern list or a familiar keyboard row.",
      recommendation:
        "Avoid familiar words and keyboard patterns, including when they are combined with symbols or digits.",
    });
  }

  if (hasRepeatedCharacterRun(value)) {
    findings.push({
      id: "repetition",
      title: "Excessive character repetition",
      explanation:
        "The same character appears four or more times consecutively.",
      recommendation:
        "Replace repeated runs with different, unrelated characters.",
    });
  }

  if (hasRepeatedSequence(value)) {
    findings.push({
      id: "repeatedSequence",
      title: "Repeated sequence",
      explanation:
        "A sequence of two or more different characters is repeated immediately, such as “abcabc”.",
      recommendation:
        "Use a unique sequence instead of repeating part of the password.",
    });
  }

  if (hasSimpleConstruction(normalized)) {
    findings.push({
      id: "construction",
      title: "Predictable construction",
      explanation:
        "The password follows a letters-then-digits pattern, a common way to modify a word.",
      recommendation:
        "Avoid appending a number string to a word; use a longer, less structured combination.",
    });
  }

  const patternPoints = Math.max(
    0,
    25 -
      findings.reduce(
        (penalty, finding) => penalty + PATTERN_PENALTIES[finding.id],
        0,
      ),
  );
  const points = {
    length: lengthPoints(length),
    categories: categoryCount * 5,
    uniqueness: uniquePoints,
    patternResistance: patternPoints,
  };
  const score =
    length === 0
      ? 0
      : Math.min(
          100,
          points.length +
            points.categories +
            points.uniqueness +
            points.patternResistance,
        );
  const band = getStrengthBand(score);

  return {
    score,
    band,
    length,
    categories,
    uniqueCount,
    points,
    findings,
  };
}

function secureRandomIndex(maxExclusive, cryptoProvider = globalThis.crypto) {
  if (!Number.isInteger(maxExclusive) || maxExclusive < 1) {
    throw new RangeError("The random selection range must be a positive integer.");
  }
  if (!cryptoProvider || typeof cryptoProvider.getRandomValues !== "function") {
    throw new Error("Secure random generation is not available in this browser.");
  }

  const range = 0x100000000;
  const acceptanceLimit = Math.floor(range / maxExclusive) * maxExclusive;
  const randomValue = new Uint32Array(1);

  do {
    cryptoProvider.getRandomValues(randomValue);
  } while (randomValue[0] >= acceptanceLimit);

  return randomValue[0] % maxExclusive;
}

function generateSecurePassword(length, selectedCategories, cryptoProvider) {
  if (!Number.isInteger(length) || length < 1 || length > 64) {
    throw new RangeError("Choose a whole-number length from 1 to 64.");
  }
  if (!Array.isArray(selectedCategories) || selectedCategories.length === 0) {
    throw new Error("Select at least one character type.");
  }
  if (selectedCategories.length > length) {
    throw new RangeError(
      "The password is too short to include every selected character type.",
    );
  }

  const pools = selectedCategories.map((category) => {
    const characters = CHARACTER_POOLS[category];
    if (!characters) throw new Error("A selected character type is invalid.");
    return characters;
  });
  const allCharacters = pools.join("");
  const result = pools.map(
    (pool) => pool[secureRandomIndex(pool.length, cryptoProvider)],
  );

  while (result.length < length) {
    result.push(allCharacters[secureRandomIndex(allCharacters.length, cryptoProvider)]);
  }

  for (let index = result.length - 1; index > 0; index -= 1) {
    const swapIndex = secureRandomIndex(index + 1, cryptoProvider);
    [result[index], result[swapIndex]] = [result[swapIndex], result[index]];
  }

  return result.join("");
}

function renderAnalysis(password) {
  const results = document.getElementById("analysisResults");
  const result = analyzePassword(password);
  const band = result.band;
  const meter = document.getElementById("strengthMeter");
  const fill = document.getElementById("strengthFill");
  const label = document.getElementById("strengthLabel");
  const scoreValue = document.getElementById("scoreValue");
  const lengthPointsValue = document.getElementById("lengthPoints");
  const lengthDetail = document.getElementById("lengthDetail");
  const categoryPointsValue = document.getElementById("categoryPoints");
  const categoryDetail = document.getElementById("categoryDetail");
  const uniquenessPointsValue = document.getElementById("uniquenessPoints");
  const uniquenessDetail = document.getElementById("uniquenessDetail");
  const patternPointsValue = document.getElementById("patternPoints");
  const patternDetail = document.getElementById("patternDetail");
  const summary = document.getElementById("assessmentSummary");
  const findingsList = document.getElementById("findingsList");
  const findingCount = document.getElementById("findingCount");
  const categoryNames = {
    uppercase: "Uppercase",
    lowercase: "Lowercase",
    numbers: "Numbers",
    symbols: "Symbols",
  };
  const categoriesPresent = Object.entries(result.categories)
    .filter(([, present]) => present)
    .map(([category]) => categoryNames[category]);

  results.hidden = false;
  label.textContent = band.name;
  label.dataset.level = band.key;
  scoreValue.textContent = String(result.score);
  lengthPointsValue.textContent = `${result.points.length} / 40`;
  lengthDetail.textContent = `${result.length} characters`;
  categoryPointsValue.textContent = `${result.points.categories} / 20`;
  categoryDetail.textContent =
    categoriesPresent.length > 0 ? categoriesPresent.join(", ") : "None";
  uniquenessPointsValue.textContent = `${result.points.uniqueness} / 15`;
  uniquenessDetail.textContent = `${result.uniqueCount} unique`;
  patternPointsValue.textContent = `${result.points.patternResistance} / 25`;
  patternDetail.textContent =
    result.findings.length === 0
      ? "No listed patterns"
      : `${result.findings.length} detected`;
  meter.setAttribute("aria-valuenow", String(result.score));
  meter.setAttribute(
    "aria-valuetext",
    `${band.name}, ${result.score} out of 100 rule-based points`,
  );
  meter.dataset.level = band.key;
  const bandIndex = STRENGTH_BANDS.findIndex((b) => b.key === band.key);
  const activeSegments = result.score > 0 ? (bandIndex >= 0 ? bandIndex + 1 : 1) : 0;
  meter.dataset.segments = String(activeSegments);
  const segments = meter.querySelectorAll(".strength-segment");
  if (segments && segments.length > 0) {
    segments.forEach((seg, idx) => {
      if (idx < activeSegments) {
        seg.classList.add("is-active");
        seg.dataset.level = band.key;
      } else {
        seg.classList.remove("is-active");
        seg.removeAttribute("data-level");
      }
    });
  }

  // Update accessible textual segment legend
  const legendItems = document.querySelectorAll(".meter-legend-item");
  if (legendItems && legendItems.length > 0) {
    legendItems.forEach((item) => {
      if (item.dataset.level === band.key) {
        item.classList.add("is-current");
      } else {
        item.classList.remove("is-current");
      }
    });
  }

  if (fill) {
    fill.style.width = `${result.score}%`;
    fill.dataset.level = band.key;
  }
  summary.textContent = `Length: ${result.length} characters · ${Object.values(result.categories).filter(Boolean).length} of 4 character types · ${result.findings.length} detected ${result.findings.length === 1 ? "weakness" : "weaknesses"}.`;
  findingCount.textContent = `${result.findings.length} ${result.findings.length === 1 ? "finding" : "findings"}`;
  findingsList.replaceChildren();

  // Show remediation quick-action if weaknesses detected or score not in highest band
  const remediateBar = document.getElementById("auditorRemediateBar");
  if (remediateBar) {
    if (result.score < 85 || result.findings.length > 0) {
      remediateBar.style.display = "flex";
    } else {
      remediateBar.style.display = "none";
    }
  }

  if (result.findings.length === 0) {
    const item = document.createElement("li");
    item.className = "no-findings";
    item.textContent =
      "No listed patterns were detected by these rules. This is not a breach check and does not guarantee that the password is safe.";
    findingsList.append(item);
    return;
  }

  for (const finding of result.findings) {
    const item = document.createElement("li");
    item.className = "finding";

    const title = document.createElement("p");
    title.className = "finding-title";
    const marker = document.createElement("span");
    marker.className = "finding-marker";
    marker.setAttribute("aria-hidden", "true");
    title.append(marker, document.createTextNode(finding.title));

    const explanation = document.createElement("p");
    explanation.className = "finding-copy";
    explanation.textContent = finding.explanation;

    const recommendation = document.createElement("p");
    recommendation.className = "finding-recommendation";
    const prefix = document.createElement("strong");
    prefix.textContent = "Recommendation: ";
    recommendation.append(prefix, document.createTextNode(finding.recommendation));

    item.append(title, explanation, recommendation);
    findingsList.append(item);
  }

  if (typeof window !== "undefined" && typeof window.dispatchEvent === "function") {
    window.dispatchEvent(new CustomEvent("ciphercheck:passwordanalysis", { detail: { analysis: result } }));
  }
}

function initAnalyzer() {
  const input = document.getElementById("passwordInput");
  const analyzeButton = document.getElementById("analyzeButton");
  const results = document.getElementById("analysisResults");
  const auditorGenerateBtn = document.getElementById("auditorGenerateBtn");

  const analyze = () => {
    if (!input.value) {
      input.focus();
      return;
    }
    renderAnalysis(input.value);
  };

  analyzeButton.addEventListener("click", analyze);

  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      analyze();
    }
  });

  input.addEventListener("input", () => {
    if (input.value.length === 0) {
      results.hidden = true;
      const meter = document.getElementById("strengthMeter");
      if (meter) {
        meter.dataset.level = "none";
        meter.dataset.segments = "0";
        const segments = meter.querySelectorAll(".strength-segment");
        segments.forEach((seg) => {
          seg.classList.remove("is-active");
          seg.removeAttribute("data-level");
        });
      }
      const legendItems = document.querySelectorAll(".meter-legend-item");
      legendItems.forEach((item) => item.classList.remove("is-current"));
      const remediateBar = document.getElementById("auditorRemediateBar");
      if (remediateBar) remediateBar.style.display = "none";

      if (typeof window !== "undefined" && typeof window.dispatchEvent === "function") {
        window.dispatchEvent(new CustomEvent("ciphercheck:passwordanalysis", { detail: { analysis: null } }));
      }
      return;
    }
    renderAnalysis(input.value);
  });

  // Wire jump from Auditor to Generator
  if (auditorGenerateBtn) {
    auditorGenerateBtn.addEventListener("click", () => {
      const generatorEl = document.getElementById("generatorPanel");
      if (generatorEl) {
        const prefersReduced =
          typeof window !== "undefined" &&
          window.matchMedia &&
          window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        generatorEl.scrollIntoView({ behavior: prefersReduced ? "auto" : "smooth", block: "start" });
        if (typeof window !== "undefined" && window.history && window.history.pushState) {
          window.history.pushState(null, "", "#generatorPanel");
        }
        document.querySelectorAll(".sc-nav-btn").forEach((b) => {
          b.classList.remove("active");
          b.setAttribute("aria-selected", "false");
        });
        const navBtnGenerator = document.getElementById("navBtnGenerator");
        if (navBtnGenerator) {
          navBtnGenerator.classList.add("active");
          navBtnGenerator.setAttribute("aria-selected", "true");
        }
        const lengthInput = document.getElementById("lengthInput");
        if (lengthInput && Number(lengthInput.value) < 20) {
          lengthInput.value = "20";
          lengthInput.dispatchEvent(new Event("input", { bubbles: true }));
        }
        const generateButton = document.getElementById("generateButton");
        if (generateButton) generateButton.click();
        const generatedPassword = document.getElementById("generatedPassword");
        setTimeout(() => generatedPassword?.focus(), 350);
      }
    });
  }
}

function initGenerator() {
  const lengthInput = document.getElementById("lengthInput");
  const lengthHint = document.getElementById("lengthHint");
  const categoryInputs = [
    ...document.querySelectorAll('input[name="characterType"]'),
  ];
  const output = document.getElementById("generatedPassword");
  const generateButton = document.getElementById("generateButton");
  const copyButton = document.getElementById("copyButton");
  const copyButtonText = document.getElementById("copyButtonText");
  const testInAuditorBtn = document.getElementById("testInAuditorBtn");
  const status = document.getElementById("generatorStatus");
  const presetButtons = document.querySelectorAll(".preset-btn");

  const clearOutput = () => {
    output.value = "";
    copyButton.disabled = true;
    if (testInAuditorBtn) testInAuditorBtn.disabled = true;
    if (copyButtonText) copyButtonText.textContent = "Copy";
    status.textContent = "";
    status.removeAttribute("data-state");
  };

  const selectedCategories = () =>
    categoryInputs
      .filter((input) => input.checked)
      .map((input) => input.value);

  const validateConfiguration = () => {
    const rawLength = lengthInput.value.trim();
    const length = Number(rawLength);
    const categories = selectedCategories();
    let message = "";

    if (!/^\d+$/.test(rawLength) || !Number.isInteger(length)) {
      message = "Enter a whole-number length.";
    } else if (length < 1 || length > 64) {
      message = "Choose a length from 1 to 64.";
    } else if (categories.length === 0) {
      message = "Select at least one character type.";
    } else if (categories.length > length) {
      message = `Length ${length} is too short for ${categories.length} selected character types.`;
    }

    lengthInput.setAttribute("aria-invalid", message ? "true" : "false");
    lengthHint.textContent = message || "Choose a length from 1 to 64.";
    if (message) {
      lengthHint.dataset.state = "error";
    } else {
      lengthHint.removeAttribute("data-state");
    }

    return message ? null : { length, categories };
  };

  const onConfigurationChange = () => {
    clearOutput();
    validateConfiguration();
  };

  lengthInput.addEventListener("input", () => {
    const currentVal = lengthInput.value.trim();
    presetButtons.forEach((b) => {
      if (b.dataset.preset === currentVal) {
        b.classList.add("active");
      } else {
        b.classList.remove("active");
      }
    });
    onConfigurationChange();
  });

  presetButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const val = btn.dataset.preset;
      if (val) {
        lengthInput.value = val;
        presetButtons.forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        onConfigurationChange();
        generateButton.click();
      }
    });
  });

  for (const input of categoryInputs) {
    input.addEventListener("change", onConfigurationChange);
  }

  generateButton.addEventListener("click", () => {
    clearOutput();
    const configuration = validateConfiguration();
    if (!configuration) {
      status.textContent = "Update the settings before generating a password.";
      status.dataset.state = "error";
      return;
    }

    try {
      output.value = generateSecurePassword(
        configuration.length,
        configuration.categories,
      );
      copyButton.disabled = false;
      if (testInAuditorBtn) testInAuditorBtn.disabled = false;
      status.textContent = "Generated locally with Web Crypto.";
      status.removeAttribute("data-state");
    } catch (error) {
      status.textContent =
        error instanceof Error
          ? error.message
          : "The password could not be generated.";
      status.dataset.state = "error";
    }
  });

  copyButton.addEventListener("click", async () => {
    if (!output.value) return;

    try {
      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        throw new Error("Clipboard access is unavailable.");
      }
      await navigator.clipboard.writeText(output.value);
      status.textContent = "Password copied to clipboard.";
      status.removeAttribute("data-state");
      if (copyButtonText) {
        copyButtonText.textContent = "✓ Copied";
        setTimeout(() => {
          if (copyButtonText) copyButtonText.textContent = "Copy";
        }, 1800);
      }
    } catch {
      status.textContent =
        "Could not copy automatically. Select the generated password and copy it manually.";
      status.dataset.state = "error";
    }
  });

  // Transfer generated password into Auditor
  if (testInAuditorBtn) {
    testInAuditorBtn.addEventListener("click", () => {
      if (!output.value) return;
      const pwInput = document.getElementById("passwordInput");
      if (pwInput) {
        pwInput.value = output.value;
        pwInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
      const analyzerEl = document.getElementById("analyzerPanel");
      if (analyzerEl) {
        const prefersReduced =
          typeof window !== "undefined" &&
          window.matchMedia &&
          window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        analyzerEl.scrollIntoView({ behavior: prefersReduced ? "auto" : "smooth", block: "start" });
        if (typeof window !== "undefined" && window.history && window.history.pushState) {
          window.history.pushState(null, "", "#analyzerPanel");
        }
        document.querySelectorAll(".sc-nav-btn").forEach((b) => {
          b.classList.remove("active");
          b.setAttribute("aria-selected", "false");
        });
        const navBtnAnalyzer = document.getElementById("navBtnAnalyzer");
        if (navBtnAnalyzer) {
          navBtnAnalyzer.classList.add("active");
          navBtnAnalyzer.setAttribute("aria-selected", "true");
        }
        setTimeout(() => pwInput?.focus(), 300);
      }
    });
  }

  validateConfiguration();
}

// ============================================================================
// Tool 03: URL & Link Risk Checker Engine
// ============================================================================

const URL_SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "country", "stream", "top", "tk", "ml", "ga", "cf", "gq",
  "work", "date", "kim", "men", "click", "link", "party", "gdn", "mom", "review"
]);

const URL_TWO_LEVEL_CCTLDS = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "police.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "co.nz", "net.nz", "org.nz", "govt.nz",
  "com.br", "net.br", "org.br", "gov.br",
  "com.mx", "org.mx", "edu.mx", "gob.mx",
  "co.za", "org.za", "web.za", "gov.za",
  "com.sg", "edu.sg", "gov.sg",
  "co.in", "net.in", "org.in", "gen.in", "gov.in",
  "com.cn", "net.cn", "org.cn", "gov.cn",
  "com.hk", "org.hk", "edu.hk", "gov.hk",
  "co.kr", "or.kr", "go.kr", "re.kr",
  "com.tw", "org.tw", "gov.tw", "idv.tw",
  "com.ar", "gob.ar",
  "com.co", "gov.co",
  "co.id", "web.id", "go.id",
  "com.my", "net.my", "org.my", "gov.my",
  "com.ph", "gov.ph",
  "com.tr", "org.tr", "gov.tr",
  "com.vn", "gov.vn",
  "co.il", "gov.il",
  "co.th", "go.th",
  "com.pk", "org.pk",
  "com.ng", "gov.ng",
  "com.pl", "com.pt", "com.es"
]);

const URL_BRAND_PATTERNS = [
  { name: "PayPal", key: "paypal", official: ["paypal.com", "paypal.me", "paypal-community.com"] },
  { name: "Google", key: "google", official: ["google.com", "google.co.uk", "google.ca", "google.de", "google.fr", "google.com.au", "google.co.jp", "googleapis.com", "gstatic.com"] },
  { name: "Apple", key: "apple", official: ["apple.com", "icloud.com", "appleid.apple.com"] },
  { name: "Microsoft", key: "microsoft", official: ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com", "msn.com"] },
  { name: "Amazon", key: "amazon", official: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp", "amazon.ca", "aws.amazon.com"] },
  { name: "Netflix", key: "netflix", official: ["netflix.com"] },
  { name: "Chase", key: "chase", official: ["chase.com", "jpmorganchase.com"] },
  { name: "Bank of America", key: "bankofamerica", official: ["bankofamerica.com", "bofa.com"] },
  { name: "Wells Fargo", key: "wellsfargo", official: ["wellsfargo.com"] },
  { name: "Meta / Facebook", key: "facebook", official: ["facebook.com", "fb.com", "meta.com"] },
  { name: "Instagram", key: "instagram", official: ["instagram.com"] },
  { name: "Dropbox", key: "dropbox", official: ["dropbox.com"] },
  { name: "Coinbase", key: "coinbase", official: ["coinbase.com"] },
  { name: "Binance", key: "binance", official: ["binance.com"] },
  { name: "Steam", key: "steam", official: ["steampowered.com", "steamcommunity.com"] },
  { name: "Discord", key: "discord", official: ["discord.com", "discord.gg"] },
  { name: "GitHub", key: "github", official: ["github.com", "github.io", "github.blog"] },
];

const URL_PHISHING_MODIFIERS = [
  "login", "signin", "sign-in", "log-in", "verify", "verification",
  "security", "secure", "update", "support", "account", "portal",
  "auth", "billing", "wallet", "recover", "recovery", "alert",
  "help", "service", "customer", "banking", "online", "client",
  "protect", "confirm", "validation", "id", "safe", "center"
];

function checkBrandToken(token, brandKey) {
  const t = token.toLowerCase();
  if (t === brandKey) {
    return { matched: true, type: "exact", token: t };
  }

  // Leetspeak / typosquatting normalization (0 -> o, 1 -> l, 3 -> e, 5 -> s, @ -> a)
  const leetNormalized = t
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/@/g, "a");

  if (leetNormalized !== t && leetNormalized === brandKey) {
    return { matched: true, type: "typosquatting", token: t };
  }

  // Brand + modifier or modifier + brand (e.g. paypallogin, applesupport, chaseonline, loginpaypal)
  for (const mod of URL_PHISHING_MODIFIERS) {
    if (t === brandKey + mod || t === mod + brandKey) {
      return { matched: true, type: "compound", token: t };
    }
    if (leetNormalized === brandKey + mod || leetNormalized === mod + brandKey) {
      return { matched: true, type: "typosquatting_compound", token: t };
    }
  }

  return { matched: false };
}

function extractDomainParts(hostname) {
  if (!hostname) {
    return { isIp: false, registeredDomain: "", subdomains: [], subdomain: "", mainLabel: "" };
  }

  // Strip trailing FQDN dot and lowercase
  const h = hostname.toLowerCase().replace(/\.+$/, "");

  // Check IPv4
  const ipv4Regex = /^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  if (ipv4Regex.test(h)) {
    return { isIp: true, registeredDomain: h, subdomains: [], subdomain: "", mainLabel: h };
  }

  // Check IPv6
  if ((h.startsWith("[") && h.endsWith("]")) || (h.includes(":") && !h.includes("."))) {
    return { isIp: true, registeredDomain: h, subdomains: [], subdomain: "", mainLabel: h };
  }

  const parts = h.split(".");
  if (parts.length <= 1) {
    return { isIp: false, registeredDomain: h, subdomains: [], subdomain: "", mainLabel: h };
  }

  let registeredDomain = h;
  let subdomains = [];
  let mainLabel = parts[0];

  if (parts.length >= 3) {
    const lastTwo = parts.slice(-2).join(".");
    if (URL_TWO_LEVEL_CCTLDS.has(lastTwo)) {
      registeredDomain = parts.slice(-3).join(".");
      subdomains = parts.slice(0, -3);
      mainLabel = parts[parts.length - 3];
    } else {
      registeredDomain = parts.slice(-2).join(".");
      subdomains = parts.slice(0, -2);
      mainLabel = parts[parts.length - 2];
    }
  } else if (parts.length === 2) {
    registeredDomain = parts.join(".");
    subdomains = [];
    mainLabel = parts[0];
  }

  return {
    isIp: false,
    registeredDomain,
    subdomains,
    subdomain: subdomains.join("."),
    mainLabel,
  };
}

function analyzeUrl(rawInput) {
  if (typeof rawInput !== "string") {
    return { isValid: false, error: "Please enter a valid URL string." };
  }

  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { isValid: false, error: "Please enter a URL to inspect." };
  }

  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  const explicitScheme = schemeMatch ? schemeMatch[1].toLowerCase() : null;

  let parseTarget = trimmed;
  let inferredScheme = false;

  if (!explicitScheme) {
    parseTarget = `http://${trimmed}`;
    inferredScheme = true;
  }

  let parsed = null;
  try {
    parsed = new URL(parseTarget);
  } catch (_) {
    return {
      isValid: false,
      rawInput: trimmed,
      error: "The entered text is not a valid URL structure. Please check the spelling or format (e.g. https://example.com/path).",
    };
  }

  const findings = [];
  const facts = [];

  const protocol = parsed.protocol.toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  const domainInfo = extractDomainParts(hostname);

  // Facts
  facts.push({
    label: "Protocol / Scheme",
    value: inferredScheme ? "http (inferred, none specified)" : parsed.protocol.replace(":", ""),
  });
  facts.push({
    label: "Host / Domain",
    value: parsed.hostname || "(none)",
  });
  facts.push({
    label: "Registered Domain",
    value: domainInfo.registeredDomain || "(none)",
  });
  facts.push({
    label: "Subdomain(s)",
    value: domainInfo.subdomain || "(none)",
  });
  facts.push({
    label: "Port",
    value: parsed.port ? parsed.port : (parsed.protocol === "https:" ? "443 (default HTTPS)" : (parsed.protocol === "http:" ? "80 (default HTTP)" : "default")),
  });
  facts.push({
    label: "Path",
    value: parsed.pathname || "/",
  });
  facts.push({
    label: "Query Parameters",
    value: parsed.search ? parsed.search : "(none)",
  });
  facts.push({
    label: "URL Length",
    value: `${trimmed.length} characters`,
  });

  // Heuristic Checks

  // 1. Dangerous / Executable Pseudo-Protocols
  const dangerousSchemes = ["javascript", "data", "vbscript", "file", "blob", "about"];
  if (explicitScheme && dangerousSchemes.includes(explicitScheme)) {
    findings.push({
      id: "dangerous-protocol",
      title: "Dangerous / Executable URL Scheme",
      severity: "high",
      explanation: `The URL uses the '${explicitScheme}:' pseudo-protocol rather than a standard web protocol (HTTP/HTTPS).`,
      whyItMatters: `Opening '${explicitScheme}:' links can execute arbitrary scripts directly in the client context or access local system files without user authorization.`,
    });
  }

  // 2. HTTP vs HTTPS
  if (protocol === "http:") {
    findings.push({
      id: "unencrypted-http",
      title: "Unencrypted Plaintext Protocol (HTTP)",
      severity: "warning",
      explanation: "The URL specifies standard unencrypted HTTP rather than secure HTTPS.",
      whyItMatters: "HTTP traffic is transmitted in cleartext and can be monitored, stolen, or altered by anyone on the local network (such as public Wi-Fi). Legitimate authentication and data services almost universally enforce HTTPS.",
    });
  }

  // 3. Raw IP Address Host
  if (domainInfo.isIp) {
    findings.push({
      id: "raw-ip-host",
      title: "Raw IP Address Used as Host",
      severity: "suspicious",
      explanation: `The URL connects directly to an IP address (${hostname}) instead of a registered domain name.`,
      whyItMatters: "Legitimate websites almost always use branded domain names. Attackers often use raw IP addresses to host malicious servers without registering domains or to bypass domain-based reputation filters.",
    });
  }

  // 4. Deceptive Embedded Credentials / Authority (@ symbol trick)
  // Only triggers when '@' occurs in the authority component before the host (e.g. https://target.com@attacker.com)
  // NOT when '@' is in path (/user/@handle) or query string (?email=user@domain.com).
  const authorityPart = trimmed.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "").split(/[\/?#]/)[0] || "";
  const hasAuthorityAt = Boolean(parsed.username || parsed.password || authorityPart.includes("@"));

  if (hasAuthorityAt) {
    findings.push({
      id: "embedded-credentials",
      title: "Deceptive Embedded Authority (@ Symbol)",
      severity: "high",
      explanation: `Observable indicator: The URL contains an '@' character in the authority portion before the host. The browser connects to '${hostname}', ignoring credentials or text preceding the '@'.`,
      whyItMatters: "This is a classic phishing deception (e.g. 'https://trusted-bank.com@evil-site.net') designed to mislead victims who only glance at the front of the URL.",
    });
  }

  // 5. Punycode (IDN) & Homoglyph
  if (hostname.includes("xn--")) {
    findings.push({
      id: "punycode-domain",
      title: "Punycode Encoded Domain (IDN)",
      severity: "warning",
      explanation: `The hostname uses Punycode (${hostname}) to encode non-ASCII characters into an ASCII string.`,
      whyItMatters: "While used legitimately for internationalized domain names in native scripts, attackers frequently use Punycode for homoglyph attacks—registering visually indistinguishable lookalike characters (such as Cyrillic 'а' replacing Latin 'a') to mimic trusted domains.",
    });
  }

  // 6. Invisible / Zero-width / Control characters
  const hiddenCharsRegex = /[\u200B-\u200D\uFEFF\u00AD\u202E\u202D\u200E\u200F\r\n\t]/;
  if (hiddenCharsRegex.test(trimmed)) {
    findings.push({
      id: "hidden-characters",
      title: "Invisible or Directional Control Characters",
      severity: "high",
      explanation: "The link contains invisible, zero-width, or bidirectional control characters.",
      whyItMatters: "These characters are hidden from human view in address bars and link previews, and are frequently weaponized to spoof visual destinations or evade spam detection.",
    });
  }

  // 7. Excessive Subdomains
  if (domainInfo.subdomains.length >= 3) {
    findings.push({
      id: "excessive-subdomains",
      title: "Excessive Subdomain Hierarchy",
      severity: "warning",
      explanation: `The hostname contains ${domainInfo.subdomains.length} subdomain levels ('${domainInfo.subdomain}').`,
      whyItMatters: "Phishing operators frequently chain subdomains together to place familiar brand names (e.g. 'paypal.com.account.verify.evil.com') at the front of long hostnames.",
    });
  }

  // 8. Brand Impersonation / Typosquatting
  for (const brand of URL_BRAND_PATTERNS) {
    const isOfficial = brand.official.some((off) => {
      return domainInfo.registeredDomain === off || hostname.endsWith("." + off);
    });
    if (isOfficial) continue;

    let brandMatch = null;
    const allLabels = hostname.split(".");
    for (const label of allLabels) {
      // Split label on hyphens and underscores to evaluate discrete tokens
      const tokens = label.split(/[-_]+/);
      for (const token of tokens) {
        const res = checkBrandToken(token, brand.key);
        if (res.matched) {
          const isSub = domainInfo.subdomains.some((s) => s.includes(label));
          brandMatch = {
            token: res.token,
            type: res.type,
            isSubdomain: isSub,
          };
          break;
        }
      }
      if (brandMatch) break;
    }

    if (brandMatch) {
      let explanation;
      if (brandMatch.type.startsWith("typosquatting")) {
        explanation = `Observable indicator: The domain contains '${brandMatch.token}', a typosquatting / character substitution permutation of '${brand.name}' ('${brand.key}'). Target destination host: '${domainInfo.registeredDomain}'.`;
      } else if (brandMatch.isSubdomain) {
        explanation = `Observable indicator: The brand name '${brand.name}' ('${brandMatch.token}') appears in subdomain '${domainInfo.subdomain}', while the actual destination host is '${domainInfo.registeredDomain}'.`;
      } else {
        explanation = `Observable indicator: The registered domain '${domainInfo.registeredDomain}' incorporates the brand name '${brand.name}' ('${brandMatch.token}'), but is not an official domain for that service.`;
      }

      findings.push({
        id: `brand-impersonation-${brand.key}`,
        title: brandMatch.type.startsWith("typosquatting")
          ? `Potential Typosquatting / Lookalike Brand ('${brand.name}')`
          : `Potential Brand Impersonation in Domain ('${brand.name}')`,
        severity: "suspicious",
        explanation,
        whyItMatters: "Phishing operators frequently construct lookalike domains or deceptive subdomain chains mimicking trusted services to deceive users into disclosing credentials or financial details. (This is a structural heuristic warning, not a live threat intelligence confirmation).",
      });
    }
  }

  // 8b. Deceptive TLD inside Subdomain Structure (e.g. brand.com.attacker.net)
  const deceptiveTldsInSub = ["com", "net", "org", "gov", "edu", "io", "co", "uk", "us", "de", "ca", "app", "dev"];
  const hasTldInSubdomain = domainInfo.subdomains.some((s) => deceptiveTldsInSub.includes(s));
  if (hasTldInSubdomain) {
    findings.push({
      id: "embedded-tld-subdomain",
      title: "Deceptive TLD in Subdomain Structure",
      severity: "suspicious",
      explanation: `Observable indicator: The subdomain structure ('${domainInfo.subdomain}') contains a top-level domain label (such as '.com' or '.net') preceding the actual destination domain ('${domainInfo.registeredDomain}').`,
      whyItMatters: "Attackers frequently create subdomains formatted like complete domains (e.g. 'paypal.com.account-verify.net') so users who only glance at the front of the URL mistakenly believe they are visiting the brand's primary site.",
    });
  }

  // 9. High-Abuse / File-Extension TLD
  const tld = hostname.split(".").pop();
  if (tld && URL_SUSPICIOUS_TLDS.has(tld)) {
    findings.push({
      id: "suspicious-tld",
      title: `High-Abuse or File-Extension TLD ('.${tld}')`,
      severity: "notice",
      explanation: `The domain uses the '.${tld}' top-level domain.`,
      whyItMatters: "TLDs such as '.zip' and '.mov' can be confused with file formats, and certain low-cost TLDs have historically experienced high abuse rates in automated spam campaigns. (A TLD alone does not confirm malice).",
    });
  }

  // 10. Non-Standard Web Port
  if (parsed.port && parsed.port !== "80" && parsed.port !== "443") {
    findings.push({
      id: "non-standard-port",
      title: `Non-Standard Web Port (:${parsed.port})`,
      severity: "warning",
      explanation: `The URL connects through port ${parsed.port} rather than the standard web ports (80 for HTTP, 443 for HTTPS).`,
      whyItMatters: "Production consumer websites rarely direct visitors to custom ports. Custom ports can indicate test environments, unhardened services, or evasion attempts.",
    });
  }

  // 11. Suspicious Character Encoding Obfuscation
  // Evaluates path separators / traversal in path, null bytes, hostname encoding, or query traversal.
  // Avoids false positives on legitimate encoded query parameters (such as search queries with '%', or encoded redirect URIs).
  if (/(%00|\0)/i.test(trimmed)) {
    findings.push({
      id: "suspicious-encoding",
      title: "Null Byte Injection Sequence (%00)",
      severity: "high",
      explanation: "Observable indicator: The URL contains a null byte (%00) injection sequence.",
      whyItMatters: "Null bytes are historically weaponized to exploit backend string termination vulnerabilities and bypass file-extension validation.",
    });
  } else {
    const pathBeforeQuery = trimmed.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\/?#]+/, "").split(/[?#]/)[0] || "";
    const isPathEncoded = /(%2e|%2f|%5c|%252e|%252f|%255c)/i.test(pathBeforeQuery) || /(%2e|%2f|%5c|%252e|%252f|%255c)/i.test(parsed.pathname);
    const isHostEncoded = /%[0-9a-f]{2}/i.test(parsed.hostname);
    const isQueryTraversal = /(%2e%2e|\.\.%2f|\.\.%5c|%252e%252e)/i.test(parsed.search);

    if (isPathEncoded) {
      findings.push({
        id: "suspicious-encoding",
        title: "Suspicious Path-Encoding Obfuscation",
        severity: "warning",
        explanation: "Observable indicator: The URL path contains percent-encoded path separators (%2f, %5c) or dot sequences (%2e).",
        whyItMatters: "Encoding slashes or dots in the URL path is commonly used to evade Web Application Firewall (WAF) path filters, hide traversal payloads, or exploit normalization discrepancies.",
      });
    } else if (isHostEncoded) {
      findings.push({
        id: "suspicious-encoding",
        title: "Percent-Encoded Hostname Obfuscation",
        severity: "warning",
        explanation: "Observable indicator: The hostname contains percent-encoded character sequences.",
        whyItMatters: "Encoding characters in domain names can be used to disguise the destination host from casual inspection and filter rules.",
      });
    } else if (isQueryTraversal) {
      findings.push({
        id: "suspicious-encoding",
        title: "Path Traversal Sequence in Query Parameters",
        severity: "warning",
        explanation: "Observable indicator: The query string contains directory traversal sequences (such as '..%2f' or '%2e%2e').",
        whyItMatters: "Traversal sequences in query parameters frequently target local file inclusion (LFI) or arbitrary file read vulnerabilities on backend servers.",
      });
    }
  }

  // 12. Consecutive Slashes / Backslashes
  if (parsed.pathname.includes("//") || trimmed.includes("\\")) {
    findings.push({
      id: "path-anomaly",
      title: "Consecutive Slashes or Backslashes in Path",
      severity: "notice",
      explanation: "The URL contains multiple consecutive forward slashes ('//') or backslashes ('\\') in the path.",
      whyItMatters: "Server implementations handle consecutive slashes and backslashes inconsistently, which can result in path normalization discrepancies or open redirects.",
    });
  }

  // 13. Abnormally Long URL
  if (trimmed.length > 250) {
    findings.push({
      id: "excessive-length",
      title: `Abnormally Long URL (${trimmed.length} characters)`,
      severity: "notice",
      explanation: "The link exceeds 250 characters in length.",
      whyItMatters: "Extremely long URLs are sometimes used in tracking redirect chains or to push suspicious domain names off-screen on mobile devices.",
    });
  }

  // Verdict Calculation
  let severityScore = 0;
  for (const f of findings) {
    if (f.severity === "high") severityScore += 15;
    else if (f.severity === "suspicious") severityScore += 7;
    else if (f.severity === "warning") severityScore += 3;
    else severityScore += 1;
  }

  let verdict;
  if (findings.length === 0) {
    verdict = {
      level: "clean",
      title: "No Obvious Red Flags Detected",
      summary: "No suspicious structural indicators were detected in the checks performed.",
    };
  } else if (severityScore >= 12 || findings.some((f) => f.severity === "high")) {
    verdict = {
      level: "high",
      title: "High Risk / Suspicious Indicators",
      summary: "Strong indicators of deception, evasion, or hostile URL structures were detected.",
    };
  } else if (severityScore >= 6 || findings.some((f) => f.severity === "suspicious")) {
    verdict = {
      level: "medium",
      title: "Elevated Caution / Heuristic Warnings",
      summary: "Multiple warning flags were detected that warrant elevated caution.",
    };
  } else {
    verdict = {
      level: "low",
      title: "Low Heuristic Concern",
      summary: "Minor structural anomalies or non-standard attributes were noted.",
    };
  }

  const disclaimers = [
    "Heuristic analysis evaluates the structural format and text patterns of a URL without fetching external servers or downloading files.",
    "HTTPS provides encrypted transit between your browser and the server, but does NOT guarantee the destination site is legitimate or safe.",
    "The absence of detected indicators does NOT establish that a website is free of malware, phishing forms, or other threats.",
    "CipherCheck does not query live threat-intelligence APIs or blocklists for this local check.",
  ];

  return {
    isValid: true,
    rawInput: trimmed,
    normalizedUrl: parsed.href,
    urlParts: {
      protocol: parsed.protocol.replace(":", ""),
      hostname: parsed.hostname,
      registeredDomain: domainInfo.registeredDomain,
      subdomain: domainInfo.subdomain,
      port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
      pathname: parsed.pathname || "/",
      search: parsed.search || "",
      hash: parsed.hash || "",
      username: parsed.username || "",
      password: parsed.password || "",
    },
    verdict,
    facts,
    findings,
    disclaimers,
  };
}

function formatUrlReport(analysis) {
  if (!analysis || !analysis.isValid) {
    return "No valid analysis available to export.";
  }

  const lines = [
    "================================================================================",
    "CIPHERCHECK — LINK & URL RISK ANALYSIS REPORT",
    "================================================================================",
    `Target URL:      ${analysis.rawInput}`,
    `Generated:       ${new Date().toISOString()}`,
    `Assessment Type: Local Static Structural Heuristic (Zero Outbound Requests)`,
    "",
    `VERDICT: ${analysis.verdict.title.toUpperCase()}`,
    `Summary: ${analysis.verdict.summary}`,
    "",
    "OBSERVED STRUCTURAL FACTS:",
  ];

  for (const fact of analysis.facts) {
    lines.push(`- ${fact.label}: ${fact.value}`);
  }

  lines.push("");
  lines.push(`DETECTED STRUCTURAL INDICATORS (${analysis.findings.length}):`);

  if (analysis.findings.length === 0) {
    lines.push("- None. No obvious red flags detected in the checks performed.");
  } else {
    for (const f of analysis.findings) {
      lines.push(`[${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(`  Explanation:    ${f.explanation}`);
      lines.push(`  Why it matters: ${f.whyItMatters}`);
      lines.push("");
    }
  }

  lines.push("DISCLAIMERS & HEURISTIC LIMITATIONS:");
  for (const d of analysis.disclaimers) {
    lines.push(`* ${d}`);
  }

  lines.push("================================================================================");
  return lines.join("\n");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function initUrlChecker() {
  const urlInput = document.getElementById("urlInput");
  const analyzeBtn = document.getElementById("analyzeUrlButton");
  const urlResults = document.getElementById("urlResults");
  const urlErrorStatus = document.getElementById("urlErrorStatus");
  const urlVerdictCard = document.getElementById("urlVerdictCard");
  const urlVerdictTitle = document.getElementById("urlVerdictTitle");
  const urlVerdictSummary = document.getElementById("urlVerdictSummary");
  const urlFindingCount = document.getElementById("urlFindingCount");
  const urlFactsGrid = document.getElementById("urlFactsGrid");
  const urlFindingsList = document.getElementById("urlFindingsList");
  const urlFindingsCounter = document.getElementById("urlFindingsCounter");
  const copyUrlReportBtn = document.getElementById("copyUrlReportBtn");
  const copyUrlFeedback = document.getElementById("copyUrlFeedback");
  const saveUrlReportBtn = document.getElementById("saveUrlReportBtn");
  const saveUrlReportLabel = document.getElementById("saveUrlReportLabel");
  const sampleBtns = document.querySelectorAll(".sample-url-btn");

  if (!urlInput || !analyzeBtn || !urlResults) return;

  let currentAnalysis = null;

  function runAnalysis() {
    const val = urlInput.value;
    if (urlErrorStatus) {
      urlErrorStatus.style.display = "none";
      urlErrorStatus.textContent = "";
    }

    if (saveUrlReportBtn) {
      saveUrlReportBtn.disabled = false;
    }
    if (saveUrlReportLabel) {
      saveUrlReportLabel.textContent = "Save Report";
    }

    const res = analyzeUrl(val);
    if (!res.isValid) {
      urlResults.hidden = true;
      if (urlErrorStatus) {
        urlErrorStatus.textContent = res.error || "Please enter a valid URL.";
        urlErrorStatus.dataset.state = "error";
        urlErrorStatus.style.display = "block";
      }
      return;
    }

    currentAnalysis = res;

    // Verdict Card
    if (urlVerdictCard) {
      urlVerdictCard.setAttribute("data-verdict", res.verdict.level);
    }
    if (urlVerdictTitle) {
      urlVerdictTitle.textContent = res.verdict.title;
    }
    if (urlVerdictSummary) {
      urlVerdictSummary.textContent = res.verdict.summary;
    }
    if (urlFindingCount) {
      urlFindingCount.textContent = `${res.findings.length} indicator${res.findings.length === 1 ? "" : "s"} detected`;
    }

    // Facts Grid
    if (urlFactsGrid) {
      urlFactsGrid.innerHTML = "";
      for (const fact of res.facts) {
        const item = document.createElement("div");
        item.className = "url-fact-item";
        item.innerHTML = `<dt>${escapeHtml(fact.label)}</dt><dd>${escapeHtml(fact.value)}</dd>`;
        urlFactsGrid.appendChild(item);
      }
    }

    // Findings List
    if (urlFindingsList) {
      urlFindingsList.innerHTML = "";
      if (urlFindingsCounter) {
        urlFindingsCounter.textContent = `${res.findings.length} finding${res.findings.length === 1 ? "" : "s"}`;
      }

      if (res.findings.length === 0) {
        const noFindings = document.createElement("li");
        noFindings.className = "url-no-findings";
        noFindings.innerHTML = `
          <svg viewBox="0 0 20 20" fill="none" width="18" height="18" aria-hidden="true">
            <circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="1.5" />
            <path d="m6.5 10 2.5 2.5 4.5-5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
          <span>No obvious structural red flags detected in the checks performed. Remember to stay vigilant.</span>
        `;
        urlFindingsList.appendChild(noFindings);
      } else {
        for (const finding of res.findings) {
          const li = document.createElement("li");
          li.className = "url-finding-item";
          li.setAttribute("data-severity", finding.severity);
          li.innerHTML = `
            <div class="url-finding-head">
              <h5 class="url-finding-title">${escapeHtml(finding.title)}</h5>
              <span class="url-finding-severity">${escapeHtml(finding.severity)}</span>
            </div>
            <p class="url-finding-explanation">${escapeHtml(finding.explanation)}</p>
            <p class="url-finding-matters"><strong>Why it matters:</strong> ${escapeHtml(finding.whyItMatters)}</p>
          `;
          urlFindingsList.appendChild(li);
        }
      }
    }

    urlResults.hidden = false;

    if (typeof window !== "undefined" && typeof window.dispatchEvent === "function") {
      window.dispatchEvent(new CustomEvent("ciphercheck:urlanalysis", { detail: { analysis: res } }));
    }
  }

  analyzeBtn.addEventListener("click", runAnalysis);

  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      runAnalysis();
    }
  });

  sampleBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const sample = btn.getAttribute("data-sample");
      if (sample) {
        urlInput.value = sample;
        runAnalysis();
      }
    });
  });

  if (copyUrlReportBtn) {
    copyUrlReportBtn.addEventListener("click", async () => {
      if (!currentAnalysis) return;
      const report = formatUrlReport(currentAnalysis);
      try {
        if (!navigator.clipboard || !navigator.clipboard.writeText) {
          throw new Error("Clipboard unavailable");
        }
        await navigator.clipboard.writeText(report);
        if (copyUrlFeedback) {
          copyUrlFeedback.textContent = "✓ Report copied to clipboard!";
          setTimeout(() => {
            copyUrlFeedback.textContent = "";
          }, 3000);
        }
      } catch (_) {
        if (copyUrlFeedback) {
          copyUrlFeedback.textContent = "Could not copy automatically. Please copy report text manually.";
        }
      }
    });
  }

  if (saveUrlReportBtn) {
    saveUrlReportBtn.addEventListener("click", async () => {
      if (!currentAnalysis) return;

      const user = window.CipherCheckAuth?.getCurrentUser();
      const token = sessionStorage.getItem("ciphercheck_token");
      if (!user && !token) {
        if (copyUrlFeedback) {
          copyUrlFeedback.textContent = "Please sign in or register to save reports to your dashboard.";
          setTimeout(() => {
            if (copyUrlFeedback.textContent.includes("Please sign in")) {
              copyUrlFeedback.textContent = "";
            }
          }, 4500);
        }
        window.CipherCheckAuth?.openAuthModal();
        return;
      }

      saveUrlReportBtn.disabled = true;
      if (saveUrlReportLabel) saveUrlReportLabel.textContent = "Saving...";

      try {
        const headers = window.CipherCheckAuth?.getAuthHeaders() || {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        };
        const res = await fetch("/api/reports", {
          method: "POST",
          headers,
          credentials: "include",
          body: JSON.stringify({ analysis: currentAnalysis }),
        });

        const data = await res.json();
        if (res.status === 201 && data.success) {
          if (saveUrlReportLabel) saveUrlReportLabel.textContent = "✓ Saved to Dashboard";
          if (copyUrlFeedback) {
            copyUrlFeedback.textContent = "✓ Report saved to your private dashboard!";
            setTimeout(() => {
              if (copyUrlFeedback.textContent.includes("✓ Report saved")) {
                copyUrlFeedback.textContent = "";
              }
            }, 3500);
          }
          window.dispatchEvent(new CustomEvent("ciphercheck:reportschanged"));
        } else if (res.status === 401) {
          saveUrlReportBtn.disabled = false;
          if (saveUrlReportLabel) saveUrlReportLabel.textContent = "Save Report";
          if (copyUrlFeedback) {
            copyUrlFeedback.textContent = "Session expired. Please sign in again.";
          }
          window.CipherCheckAuth?.openAuthModal();
        } else {
          saveUrlReportBtn.disabled = false;
          if (saveUrlReportLabel) saveUrlReportLabel.textContent = "Save Report";
          if (copyUrlFeedback) {
            copyUrlFeedback.textContent = data.error || "Failed to save security report.";
          }
        }
      } catch (err) {
        saveUrlReportBtn.disabled = false;
        if (saveUrlReportLabel) saveUrlReportLabel.textContent = "Save Report";
        if (copyUrlFeedback) {
          copyUrlFeedback.textContent = "Connection error. Please try again.";
        }
      }
    });
  }
}

const THEME_STORAGE_KEY = "ciphercheck-theme";

function applyTheme(theme, isUserAction = false) {
  const effectiveTheme = theme === "dark" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", effectiveTheme);

  const metaTheme = document.querySelector('meta[name="theme-color"]');
  if (metaTheme) {
    metaTheme.setAttribute(
      "content",
      effectiveTheme === "dark" ? "#0f1411" : "#f4f6f3",
    );
  }

  const toggle = document.getElementById("themeToggle");
  const label = document.getElementById("themeLabel");
  if (toggle) {
    const nextThemeLabel = effectiveTheme === "dark" ? "Light" : "Dark";
    toggle.setAttribute(
      "aria-label",
      `Switch to ${nextThemeLabel.toLowerCase()} theme`,
    );
    toggle.setAttribute(
      "title",
      `Switch to ${nextThemeLabel.toLowerCase()} theme`,
    );
    if (label) {
      label.textContent = nextThemeLabel;
    }
  }

  if (isUserAction) {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, effectiveTheme);
    } catch (_) {}
  }
}

function getStoredTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY);
  } catch (_) {
    return null;
  }
}

function getSystemTheme() {
  return window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function initThemeToggle() {
  const toggle = document.getElementById("themeToggle");
  const stored = getStoredTheme();
  const currentTheme = stored || getSystemTheme();

  applyTheme(currentTheme, false);

  if (toggle) {
    toggle.addEventListener("click", () => {
      const activeTheme =
        document.documentElement.getAttribute("data-theme") || "light";
      const newTheme = activeTheme === "dark" ? "light" : "dark";
      applyTheme(newTheme, true);
    });
  }

  if (window.matchMedia) {
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = (e) => {
      if (!getStoredTheme()) {
        applyTheme(e.matches ? "dark" : "light", false);
      }
    };
    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", handler);
    } else if (typeof mediaQuery.addListener === "function") {
      mediaQuery.addListener(handler);
    }
  }
}

function initAuth() {
  const dialog = document.getElementById("authDialog");
  const openBtn = document.getElementById("authOpenButton");
  const closeBtn = document.getElementById("authModalClose");
  const buttonLabel = document.getElementById("authButtonLabel");
  const guestView = document.getElementById("authGuestView");
  const userView = document.getElementById("authUserView");
  const tabLogin = document.getElementById("tabLogin");
  const tabRegister = document.getElementById("tabRegister");
  const panelLogin = document.getElementById("panelLogin");
  const panelRegister = document.getElementById("panelRegister");
  const panelForgot = document.getElementById("panelForgot");
  const panelReset = document.getElementById("panelReset");
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");
  const forgotForm = document.getElementById("forgotForm");
  const resetPasswordForm = document.getElementById("resetPasswordForm");
  const loginStatus = document.getElementById("loginStatus");
  const registerStatus = document.getElementById("registerStatus");
  const forgotStatus = document.getElementById("forgotStatus");
  const resetStatus = document.getElementById("resetStatus");
  const profileEmail = document.getElementById("profileEmail");
  const profileDisplayName = document.getElementById("profileDisplayName");
  const profileEmailSubtitle = document.getElementById("profileEmailSubtitle");
  const profileNicknameValue = document.getElementById("profileNicknameValue");
  const profileNicknameDisplay = document.getElementById("profileNicknameDisplay");
  const profileNicknameCard = document.getElementById("profileNicknameCard");
  const nicknameViewRow = document.getElementById("nicknameViewRow");
  const nicknameEditForm = document.getElementById("nicknameEditForm");
  const editNicknameBtn = document.getElementById("editNicknameBtn");
  const nicknameInput = document.getElementById("nicknameInput");
  const saveNicknameBtn = document.getElementById("saveNicknameBtn");
  const cancelNicknameBtn = document.getElementById("cancelNicknameBtn");
  const nicknameStatus = document.getElementById("nicknameStatus");
  const registerNickname = document.getElementById("registerNickname");
  const profileUserId = document.getElementById("profileUserId");
  const profileCreated = document.getElementById("profileCreated");
  const profileVerified = document.getElementById("profileVerified");
  const profileStatus = document.getElementById("profileStatus");
  const logoutBtn = document.getElementById("logoutButton");
  const forgotBtn = document.getElementById("forgotPasswordBtn");
  const backToLoginBtn = document.getElementById("backToLoginBtn");
  const haveResetTokenBtn = document.getElementById("haveResetTokenBtn");
  const cancelResetBtn = document.getElementById("cancelResetBtn");
  const resendVerificationBtn = document.getElementById("resendVerificationBtn");
  const resetTokenField = document.getElementById("resetTokenField");
  const resetTokenInput = document.getElementById("resetTokenInput");
  const smtpNotice = document.getElementById("smtpNotice");
  const smtpNoticeText = document.getElementById("smtpNoticeText");
  const authTabs = document.querySelector(".auth-tabs");

  let isSmtpAvailable = false;
  let currentResetToken = null;
  let currentUser = null;

  function getAuthHeaders(extra = {}) {
    const token = sessionStorage.getItem("ciphercheck_token");
    const headers = { "Content-Type": "application/json", ...extra };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    return headers;
  }

  window.CipherCheckAuth = {
    getAuthHeaders,
    getCurrentUser: () => currentUser,
    openAuthModal: () => {
      if (dialog && typeof dialog.showModal === "function") {
        dialog.showModal();
      } else if (dialog) {
        dialog.setAttribute("open", "");
      }
      if (openBtn) openBtn.setAttribute("aria-expanded", "true");
    },
  };

  const updateAuthUI = (user) => {
    currentUser = user;
    if (user) {
      const fallbackName = user.email ? user.email.split("@")[0] : "User";
      const hasNickname = Boolean(user.nickname && typeof user.nickname === "string" && user.nickname.trim());
      const displayName = hasNickname ? user.nickname.trim() : fallbackName;

      if (buttonLabel) {
        buttonLabel.textContent = displayName;
      }
      if (guestView) guestView.hidden = true;
      if (userView) userView.hidden = false;
      if (profileDisplayName) profileDisplayName.textContent = displayName;
      if (profileEmailSubtitle) profileEmailSubtitle.textContent = user.email;
      if (profileEmail) profileEmail.textContent = user.email;

      if (profileNicknameValue) {
        if (hasNickname) {
          profileNicknameValue.textContent = user.nickname.trim();
          profileNicknameValue.classList.remove("is-fallback");
        } else {
          profileNicknameValue.textContent = `${fallbackName} (fallback)`;
          profileNicknameValue.classList.add("is-fallback");
        }
      }

      if (profileNicknameDisplay) {
        profileNicknameDisplay.textContent = hasNickname ? user.nickname.trim() : "Not set";
      }

      if (nicknameViewRow) nicknameViewRow.style.display = "flex";
      if (nicknameEditForm) nicknameEditForm.style.display = "none";
      if (nicknameStatus) {
        nicknameStatus.textContent = "";
        nicknameStatus.removeAttribute("data-state");
      }

      if (profileUserId) {
        profileUserId.textContent = user.id ? `#${user.id.slice(0, 8)}...` : "—";
        profileUserId.title = user.id || "";
      }
      if (profileCreated) {
        profileCreated.textContent = new Date(user.createdAt).toLocaleDateString();
      }
      if (profileVerified) {
        if (user.isVerified) {
          profileVerified.textContent = "Verified ✓";
          profileVerified.style.color = "var(--green)";
          if (resendVerificationBtn) resendVerificationBtn.style.display = "none";
        } else {
          profileVerified.textContent = isSmtpAvailable
            ? "Pending verification"
            : "Unverified (SMTP offline)";
          profileVerified.style.color = "var(--amber)";
          if (resendVerificationBtn) {
            resendVerificationBtn.style.display = isSmtpAvailable ? "block" : "none";
          }
        }
      }
    } else {
      currentUser = null;
      if (buttonLabel) buttonLabel.textContent = "Sign in";
      if (guestView) guestView.hidden = false;
      if (userView) userView.hidden = true;
    }
    window.dispatchEvent(new CustomEvent("ciphercheck:authchange", { detail: { user } }));
  };

  if (editNicknameBtn) {
    editNicknameBtn.addEventListener("click", () => {
      if (nicknameViewRow) nicknameViewRow.style.display = "none";
      if (nicknameEditForm) nicknameEditForm.style.display = "block";
      if (nicknameInput) {
        nicknameInput.value = currentUser?.nickname || "";
        nicknameInput.focus();
        nicknameInput.select();
      }
      if (nicknameStatus) {
        nicknameStatus.textContent = "";
        nicknameStatus.removeAttribute("data-state");
      }
    });
  }

  if (cancelNicknameBtn) {
    cancelNicknameBtn.addEventListener("click", () => {
      if (nicknameEditForm) nicknameEditForm.style.display = "none";
      if (nicknameViewRow) nicknameViewRow.style.display = "flex";
      if (nicknameStatus) {
        nicknameStatus.textContent = "";
        nicknameStatus.removeAttribute("data-state");
      }
    });
  }

  if (nicknameEditForm) {
    nicknameEditForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!nicknameStatus || !nicknameInput) return;
      nicknameStatus.textContent = "";
      nicknameStatus.removeAttribute("data-state");

      const trimmed = nicknameInput.value.trim();
      if (trimmed.length < 2 || trimmed.length > 30) {
        nicknameStatus.textContent = "Nickname must be between 2 and 30 characters long.";
        nicknameStatus.dataset.state = "error";
        return;
      }

      if (/[\r\n\t\0]/.test(trimmed) || /<[^>]*>/.test(trimmed)) {
        nicknameStatus.textContent = "Nickname cannot contain HTML tags or control characters.";
        nicknameStatus.dataset.state = "error";
        return;
      }

      if (saveNicknameBtn) saveNicknameBtn.disabled = true;
      nicknameStatus.textContent = "Saving nickname...";

      try {
        const res = await fetch("/api/auth/nickname", {
          method: "PUT",
          headers: getAuthHeaders(),
          credentials: "include",
          body: JSON.stringify({ nickname: trimmed }),
        });
        const data = await res.json();
        if (res.ok && data.user) {
          currentUser = data.user;
          updateAuthUI(data.user);
          nicknameStatus.textContent = data.message || "Nickname updated successfully!";
          nicknameStatus.removeAttribute("data-state");
          setTimeout(() => {
            if (nicknameEditForm) nicknameEditForm.style.display = "none";
            if (nicknameViewRow) nicknameViewRow.style.display = "flex";
          }, 1000);
        } else {
          nicknameStatus.textContent = data.error || "Failed to update nickname.";
          nicknameStatus.dataset.state = "error";
        }
      } catch (_) {
        nicknameStatus.textContent = "Connection error while updating nickname.";
        nicknameStatus.dataset.state = "error";
      } finally {
        if (saveNicknameBtn) saveNicknameBtn.disabled = false;
      }
    });
  }

  const switchTab = (tab) => {
    if (panelForgot) panelForgot.hidden = true;
    if (panelReset) panelReset.hidden = true;
    if (resetTokenField) resetTokenField.style.display = "none";
    if (authTabs) authTabs.hidden = false;
    if (tab === "login") {
      tabLogin.classList.add("active");
      tabLogin.setAttribute("aria-selected", "true");
      tabRegister.classList.remove("active");
      tabRegister.setAttribute("aria-selected", "false");
      panelLogin.hidden = false;
      panelRegister.hidden = true;
    } else {
      tabRegister.classList.add("active");
      tabRegister.setAttribute("aria-selected", "true");
      tabLogin.classList.remove("active");
      tabLogin.setAttribute("aria-selected", "false");
      panelRegister.hidden = false;
      panelLogin.hidden = true;
    }
    if (loginStatus) {
      loginStatus.textContent = "";
      loginStatus.removeAttribute("data-state");
    }
    if (registerStatus) {
      registerStatus.textContent = "";
      registerStatus.removeAttribute("data-state");
    }
  };

  if (tabLogin) tabLogin.addEventListener("click", () => switchTab("login"));
  if (tabRegister) tabRegister.addEventListener("click", () => switchTab("register"));

  if (openBtn && dialog) {
    openBtn.addEventListener("click", () => {
      if (typeof dialog.showModal === "function") {
        dialog.showModal();
      } else {
        dialog.setAttribute("open", "");
      }
      openBtn.setAttribute("aria-expanded", "true");
    });
  }

  const closeDialog = () => {
    if (dialog) {
      if (typeof dialog.close === "function") {
        dialog.close();
      } else {
        dialog.removeAttribute("open");
      }
    }
    if (openBtn) openBtn.setAttribute("aria-expanded", "false");
  };

  if (closeBtn) closeBtn.addEventListener("click", closeDialog);
  if (dialog) {
    dialog.addEventListener("click", (e) => {
      const rect = dialog.getBoundingClientRect();
      const isInDialog =
        rect.top <= e.clientY &&
        e.clientY <= rect.top + rect.height &&
        rect.left <= e.clientX &&
        e.clientX <= rect.left + rect.width;
      if (!isInDialog) {
        closeDialog();
      }
    });
  }

  async function fetchStatus() {
    try {
      const res = await fetch("/api/auth/status");
      if (res.ok) {
        const data = await res.json();
        isSmtpAvailable = !!data.smtpConfigured;
        if (smtpNotice && smtpNoticeText) {
          if (data.smtpConfigured) {
            smtpNotice.classList.add("configured");
            smtpNoticeText.textContent =
              "✓ SMTP email service is active. Email verification and password recovery are enabled.";
          } else {
            smtpNotice.classList.remove("configured");
            smtpNoticeText.textContent =
              "SMTP is not configured in this environment. Email verification and password recovery delivery are unavailable.";
          }
        }
      }
    } catch (_) {}
  }

  async function checkSession() {
    try {
      const res = await fetch("/api/auth/me", {
        headers: getAuthHeaders(),
        credentials: "include",
      });
      if (res.ok) {
        const data = await res.json();
        updateAuthUI(data.user);
      } else {
        sessionStorage.removeItem("ciphercheck_token");
        updateAuthUI(null);
      }
    } catch (_) {
      updateAuthUI(null);
    }
  }

  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      loginStatus.textContent = "";
      loginStatus.removeAttribute("data-state");

      const email = document.getElementById("loginEmail").value.trim();
      const password = document.getElementById("loginPassword").value;

      if (!email || !password) {
        loginStatus.textContent = "Please fill in all fields.";
        loginStatus.dataset.state = "error";
        return;
      }

      try {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (res.ok && data.user) {
          if (data.token) {
            sessionStorage.setItem("ciphercheck_token", data.token);
          }
          loginStatus.textContent = "Signed in successfully.";
          updateAuthUI(data.user);
          loginForm.reset();
        } else {
          loginStatus.textContent = data.error || "Failed to sign in.";
          loginStatus.dataset.state = "error";
        }
      } catch (err) {
        loginStatus.textContent = "Connection error. Please try again.";
        loginStatus.dataset.state = "error";
      }
    });
  }

  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      registerStatus.textContent = "";
      registerStatus.removeAttribute("data-state");

      const email = document.getElementById("registerEmail").value.trim();
      const password = document.getElementById("registerPassword").value;
      const nickname = registerNickname ? registerNickname.value.trim() : "";

      if (!email || !password) {
        registerStatus.textContent = "Please fill in all required fields.";
        registerStatus.dataset.state = "error";
        return;
      }

      if (nickname && (nickname.length < 2 || nickname.length > 30)) {
        registerStatus.textContent = "Nickname must be between 2 and 30 characters.";
        registerStatus.dataset.state = "error";
        return;
      }

      if (password.length < 8) {
        registerStatus.textContent = "Password must be at least 8 characters.";
        registerStatus.dataset.state = "error";
        return;
      }

      try {
        const res = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ email, password, nickname: nickname || undefined }),
        });
        const data = await res.json();
        if (res.ok && data.user) {
          if (data.token) {
            sessionStorage.setItem("ciphercheck_token", data.token);
          }
          registerStatus.textContent = data.message || "Account created successfully.";
          updateAuthUI(data.user);
          registerForm.reset();
        } else {
          registerStatus.textContent = data.error || "Registration failed.";
          registerStatus.dataset.state = "error";
        }
      } catch (err) {
        registerStatus.textContent = "Connection error. Please try again.";
        registerStatus.dataset.state = "error";
      }
    });
  }

  if (forgotBtn) {
    forgotBtn.addEventListener("click", () => {
      if (panelLogin) panelLogin.hidden = true;
      if (panelForgot) panelForgot.hidden = false;
      if (forgotStatus) {
        forgotStatus.textContent = "";
        forgotStatus.removeAttribute("data-state");
      }
    });
  }

  if (backToLoginBtn) {
    backToLoginBtn.addEventListener("click", () => {
      if (panelForgot) panelForgot.hidden = true;
      if (panelLogin) panelLogin.hidden = false;
    });
  }

  if (haveResetTokenBtn) {
    haveResetTokenBtn.addEventListener("click", () => {
      if (panelForgot) panelForgot.hidden = true;
      if (panelReset) panelReset.hidden = false;
      if (authTabs) authTabs.hidden = true;
      if (resetTokenField) resetTokenField.style.display = "block";
      if (resetTokenInput) resetTokenInput.focus();
      if (resetStatus) {
        resetStatus.textContent = "Please enter your reset token and new password.";
        resetStatus.removeAttribute("data-state");
      }
    });
  }

  if (forgotForm) {
    forgotForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      forgotStatus.textContent = "";
      forgotStatus.removeAttribute("data-state");

      const email = document.getElementById("forgotEmail").value.trim();
      if (!email) {
        forgotStatus.textContent = "Please enter your email address.";
        forgotStatus.dataset.state = "error";
        return;
      }

      try {
        const res = await fetch("/api/auth/forgot-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        });
        const data = await res.json();
        if (res.ok) {
          forgotStatus.textContent =
            data.message || "If the account exists, a reset link has been dispatched.";
          forgotForm.reset();
        } else {
          forgotStatus.textContent = data.error || "Unable to send password reset.";
          forgotStatus.dataset.state = "error";
        }
      } catch (_) {
        forgotStatus.textContent = "Connection error. Please try again.";
        forgotStatus.dataset.state = "error";
      }
    });
  }

  if (resendVerificationBtn) {
    resendVerificationBtn.addEventListener("click", async () => {
      if (profileStatus) {
        profileStatus.textContent = "Sending verification email...";
        profileStatus.removeAttribute("data-state");
      }
      try {
        const res = await fetch("/api/auth/resend-verification", {
          method: "POST",
          headers: getAuthHeaders(),
          credentials: "include",
        });
        const data = await res.json();
        if (profileStatus) {
          if (res.ok) {
            profileStatus.textContent = data.message || "Verification email sent.";
          } else {
            profileStatus.textContent = data.error || "Failed to resend verification.";
            profileStatus.dataset.state = "error";
          }
        }
      } catch (_) {
        if (profileStatus) {
          profileStatus.textContent = "Connection error. Please try again.";
          profileStatus.dataset.state = "error";
        }
      }
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      try {
        await fetch("/api/auth/logout", {
          method: "POST",
          headers: getAuthHeaders(),
          credentials: "include",
        });
      } catch (_) {}
      sessionStorage.removeItem("ciphercheck_token");
      updateAuthUI(null);
      switchTab("login");
    });
  }

  if (cancelResetBtn) {
    cancelResetBtn.addEventListener("click", () => {
      if (panelReset) panelReset.hidden = true;
      if (authTabs) authTabs.hidden = false;
      if (resetTokenField) resetTokenField.style.display = "none";
      if (resetTokenInput) resetTokenInput.value = "";
      currentResetToken = null;
      switchTab("login");
    });
  }

  if (resetPasswordForm) {
    resetPasswordForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      resetStatus.textContent = "";
      resetStatus.removeAttribute("data-state");

      const rawToken = (currentResetToken || (resetTokenInput ? resetTokenInput.value : "")).trim();
      const token = rawToken.replace(/^.*[?&]resetToken=/, "").trim();
      const newPassword = document.getElementById("resetNewPassword").value;
      const confirmPassword = document.getElementById("resetConfirmPassword").value;

      if (!token) {
        resetStatus.textContent = "Password reset token is missing. Please enter the token from your email.";
        resetStatus.dataset.state = "error";
        return;
      }

      if (!newPassword || !confirmPassword) {
        resetStatus.textContent = "Please fill in all fields.";
        resetStatus.dataset.state = "error";
        return;
      }

      if (newPassword.length < 8) {
        resetStatus.textContent = "Password must be at least 8 characters long.";
        resetStatus.dataset.state = "error";
        return;
      }

      if (newPassword !== confirmPassword) {
        resetStatus.textContent = "Passwords do not match.";
        resetStatus.dataset.state = "error";
        return;
      }

      try {
        const res = await fetch("/api/auth/reset-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token, newPassword }),
        });
        const data = await res.json();
        if (res.ok && data.success) {
          resetStatus.textContent = "Password updated successfully! You can now sign in.";
          resetStatus.removeAttribute("data-state");
          resetPasswordForm.reset();
          currentResetToken = null;
          if (resetTokenInput) resetTokenInput.value = "";
          setTimeout(() => {
            if (panelReset) panelReset.hidden = true;
            if (authTabs) authTabs.hidden = false;
            switchTab("login");
            if (loginStatus) {
              loginStatus.textContent = "Password reset complete. Please sign in with your new password.";
              loginStatus.removeAttribute("data-state");
            }
          }, 1500);
        } else {
          resetStatus.textContent = data.error || "Password reset failed. Link may be invalid or expired.";
          resetStatus.dataset.state = "error";
        }
      } catch (_) {
        resetStatus.textContent = "Connection error. Please try again.";
        resetStatus.dataset.state = "error";
      }
    });
  }

  // Handle email verification links
  const urlParams = new URLSearchParams(window.location.search);
  const verifyToken = urlParams.get("verifyToken") || urlParams.get("token");
  if (verifyToken) {
    window.history.replaceState({}, document.title, window.location.pathname);
    fetch("/api/auth/verify-email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: verifyToken }),
    })
      .then((r) => r.json())
      .then((data) => {
        if (dialog && typeof dialog.showModal === "function") dialog.showModal();
        if (data.user) {
          if (data.token) {
            sessionStorage.setItem("ciphercheck_token", data.token);
          }
          updateAuthUI(data.user);
          if (profileStatus) {
            profileStatus.textContent = "✓ Email address verified successfully!";
            profileStatus.removeAttribute("data-state");
          }
        } else {
          switchTab("login");
          if (loginStatus) {
            loginStatus.textContent = data.error || "Verification link is invalid or has expired.";
            loginStatus.dataset.state = "error";
          }
        }
      })
      .catch(() => {
        if (dialog && typeof dialog.showModal === "function") dialog.showModal();
        switchTab("login");
        if (loginStatus) {
          loginStatus.textContent = "Connection error during email verification.";
          loginStatus.dataset.state = "error";
        }
      });
  }

  // Handle password reset links
  const resetToken = urlParams.get("resetToken");
  if (resetToken) {
    currentResetToken = resetToken;
    if (resetTokenInput) resetTokenInput.value = resetToken;
    if (resetTokenField) resetTokenField.style.display = "none";
    window.history.replaceState({}, document.title, window.location.pathname);
    if (dialog && typeof dialog.showModal === "function") dialog.showModal();
    if (guestView) guestView.hidden = false;
    if (userView) userView.hidden = true;
    if (panelLogin) panelLogin.hidden = true;
    if (panelRegister) panelRegister.hidden = true;
    if (panelForgot) panelForgot.hidden = true;
    if (panelReset) panelReset.hidden = false;
    if (authTabs) authTabs.hidden = true;
    if (resetStatus) {
      resetStatus.textContent = "Enter your new password below.";
      resetStatus.removeAttribute("data-state");
    }
  }

  fetchStatus();
  checkSession();
}

function initSecurityDashboard() {
  const dashboardGuestCard = document.getElementById("dashboardGuestCard");
  const dashboardAuthContent = document.getElementById("dashboardAuthContent");
  const dashboardSignInBtn = document.getElementById("dashboardSignInBtn");
  const dashboardSyncTag = document.getElementById("dashboardSyncTag");

  const statTotal = document.getElementById("statTotalReports");
  const statClean = document.getElementById("statCleanReports");
  const statLow = document.getElementById("statLowReports");
  const statMedium = document.getElementById("statMediumReports");
  const statHigh = document.getElementById("statHighReports");

  const searchInput = document.getElementById("dashboardSearchInput");
  const filterChips = document.querySelectorAll(".dashboard-filter-group .filter-chip");
  const refreshBtn = document.getElementById("refreshDashboardBtn");
  const clearHistoryBtn = document.getElementById("clearHistoryBtn");

  const reportsContainer = document.getElementById("dashboardReportsContainer");
  const loadingIndicator = document.getElementById("dashboardLoading");
  const emptyState = document.getElementById("dashboardEmptyState");
  const emptyMessage = document.getElementById("dashboardEmptyMessage");
  const reportsList = document.getElementById("dashboardReportsList");

  const paginationBar = document.getElementById("dashboardPaginationBar");
  const paginationInfo = document.getElementById("paginationInfo");
  const prevPageBtn = document.getElementById("prevPageBtn");
  const nextPageBtn = document.getElementById("nextPageBtn");

  const reportDetailDialog = document.getElementById("reportDetailDialog");
  const reportDetailClose = document.getElementById("reportDetailClose");
  const reportDetailModalTitle = document.getElementById("reportDetailModalTitle");
  const reportDetailBody = document.getElementById("reportDetailBody");
  const copyDetailReportBtn = document.getElementById("copyDetailReportBtn");
  const deleteDetailReportBtn = document.getElementById("deleteDetailReportBtn");
  const detailFeedback = document.getElementById("detailFeedback");

  const confirmClearDialog = document.getElementById("confirmClearDialog");
  const confirmClearClose = document.getElementById("confirmClearClose");
  const cancelClearBtn = document.getElementById("cancelClearBtn");
  const executeClearBtn = document.getElementById("executeClearBtn");

  let currentRiskFilter = "all";
  let currentSearchQuery = "";
  let currentPage = 1;
  const pageSize = 10;
  let cachedReports = [];
  let activeModalReport = null;
  let searchDebounceTimer = null;

  function updateSyncTag(isAuth) {
    if (!dashboardSyncTag) return;
    if (isAuth) {
      dashboardSyncTag.textContent = "ACCOUNT SYNCED";
      dashboardSyncTag.classList.remove("guest-mode");
    } else {
      dashboardSyncTag.textContent = "GUEST MODE";
      dashboardSyncTag.classList.add("guest-mode");
    }
  }

  function renderStats(stats = {}) {
    const total = stats.total || 0;
    const byRisk = stats.byRisk || {};
    if (statTotal) statTotal.textContent = total;
    if (statClean) statClean.textContent = byRisk.clean || 0;
    if (statLow) statLow.textContent = byRisk.low || 0;
    if (statMedium) statMedium.textContent = byRisk.medium || 0;
    if (statHigh) statHigh.textContent = byRisk.high || 0;
  }

  function getRiskBadgeLabel(risk) {
    switch (risk) {
      case "clean":
        return "No Flags";
      case "low":
        return "Low Concern";
      case "medium":
        return "Elevated Caution";
      case "high":
        return "High Risk";
      default:
        return "Recorded";
    }
  }

  function formatDisplayDate(dateStr) {
    if (!dateStr) return "";
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch (_) {
      return dateStr;
    }
  }

  async function loadDashboardData(page = 1) {
    const user = window.CipherCheckAuth?.getCurrentUser();
    const token = sessionStorage.getItem("ciphercheck_token");

    if (!user && !token) {
      if (dashboardGuestCard) dashboardGuestCard.style.display = "flex";
      if (dashboardAuthContent) dashboardAuthContent.style.display = "none";
      updateSyncTag(false);
      renderStats({});
      return;
    }

    if (dashboardGuestCard) dashboardGuestCard.style.display = "none";
    if (dashboardAuthContent) dashboardAuthContent.style.display = "block";
    updateSyncTag(true);

    if (loadingIndicator) loadingIndicator.style.display = "block";
    if (emptyState) emptyState.style.display = "none";

    const offset = (page - 1) * pageSize;
    const params = new URLSearchParams({
      limit: String(pageSize),
      offset: String(offset),
      risk: currentRiskFilter,
    });
    if (currentSearchQuery) {
      params.set("search", currentSearchQuery);
    }

    try {
      const headers = window.CipherCheckAuth?.getAuthHeaders() || {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      };

      const res = await fetch(`/api/reports?${params.toString()}`, {
        method: "GET",
        headers,
        credentials: "include",
      });

      if (res.status === 401) {
        if (dashboardGuestCard) dashboardGuestCard.style.display = "flex";
        if (dashboardAuthContent) dashboardAuthContent.style.display = "none";
        updateSyncTag(false);
        renderStats({});
        return;
      }

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to load reports");
      }

      cachedReports = data.reports || [];
      currentPage = page;
      renderStats(data.stats);

      if (typeof window !== "undefined" && typeof window.dispatchEvent === "function") {
        window.dispatchEvent(new CustomEvent("ciphercheck:reportsloaded", { detail: { stats: data.stats, reports: cachedReports } }));
      }

      const totalCount = data.pagination?.total || 0;
      renderReportsList(cachedReports, totalCount, offset);
    } catch (err) {
      console.error("[Dashboard] Error loading saved reports:", err);
      if (reportsList) reportsList.innerHTML = "";
      if (emptyState) {
        emptyState.style.display = "block";
        if (emptyMessage) {
          emptyMessage.textContent = "Unable to load saved reports at this time. Please check your connection and try again.";
        }
      }
      if (paginationBar) paginationBar.style.display = "none";
    } finally {
      if (loadingIndicator) loadingIndicator.style.display = "none";
    }
  }

  function renderReportsList(reports, totalCount, offset) {
    if (!reportsList) return;
    reportsList.innerHTML = "";

    if (!reports || reports.length === 0) {
      if (emptyState) {
        emptyState.style.display = "block";
        if (emptyMessage) {
          if (currentSearchQuery || currentRiskFilter !== "all") {
            emptyMessage.textContent = "No saved scan reports match your current filter or search criteria. Try choosing another filter or clearing your search.";
          } else {
            emptyMessage.textContent = "You haven’t saved any URL security assessments yet. Analyze a web link above and click \"Save Report\" to build your private security scan history.";
          }
        }
      }
      if (paginationBar) paginationBar.style.display = "none";
      return;
    }

    if (emptyState) emptyState.style.display = "none";

    reports.forEach((rep) => {
      const li = document.createElement("li");
      li.className = "report-card";
      li.setAttribute("data-risk", rep.riskLevel || "clean");
      li.setAttribute("data-id", rep.id);

      const badgeLabel = getRiskBadgeLabel(rep.riskLevel);
      const displayHost = rep.hostname || rep.registeredDomain || "Unknown Host";
      const displayDate = formatDisplayDate(rep.createdAt);
      const displayUrl = rep.redactedUrl || rep.url;
      const findingsCount = rep.findingsCount ?? (rep.analysisData?.findings?.length || 0);

      li.innerHTML = `
        <div class="report-card-top">
          <div class="report-card-title-group">
            <span class="report-verdict-badge ${escapeHtml(rep.riskLevel || "clean")}">${escapeHtml(badgeLabel)}</span>
            <strong class="report-card-host">${escapeHtml(displayHost)}</strong>
            ${rep.registeredDomain && rep.registeredDomain !== rep.hostname ? `<span class="report-card-domain">(${escapeHtml(rep.registeredDomain)})</span>` : ""}
          </div>
          <span class="report-card-date">${escapeHtml(displayDate)}</span>
        </div>
        <div class="report-card-url" title="${escapeHtml(displayUrl)}">${escapeHtml(displayUrl)}</div>
        <div class="report-card-summary">${escapeHtml(rep.verdictSummary || rep.verdictTitle || "Security analysis report")}</div>
        <div class="report-card-footer">
          <span class="report-card-findings-pill">${findingsCount} indicator${findingsCount === 1 ? "" : "s"}</span>
          <div class="report-card-actions">
            <button class="button button-sm button-secondary inspect-report-btn" type="button" data-id="${escapeHtml(rep.id)}">
              Inspect Findings
            </button>
            <button class="button button-sm button-outline danger-btn delete-report-btn" type="button" data-id="${escapeHtml(rep.id)}" title="Delete this saved report" aria-label="Delete report for ${escapeHtml(displayHost)}">
              <svg viewBox="0 0 16 16" fill="none" width="13" height="13" aria-hidden="true">
                <path d="M3 4h10M6 4V2.5A.5.5 0 0 1 6.5 2h3a.5.5 0 0 1 .5.5V4m2 0v9.5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </button>
          </div>
        </div>
      `;

      reportsList.appendChild(li);
    });

    // Wire pagination bar
    if (paginationBar) {
      if (totalCount > pageSize || offset > 0) {
        paginationBar.style.display = "flex";
        const start = offset + 1;
        const end = Math.min(offset + reports.length, totalCount);
        if (paginationInfo) {
          paginationInfo.textContent = `Showing ${start}–${end} of ${totalCount} saved reports`;
        }
        if (prevPageBtn) {
          prevPageBtn.disabled = currentPage <= 1;
        }
        if (nextPageBtn) {
          nextPageBtn.disabled = end >= totalCount;
        }
      } else {
        paginationBar.style.display = "none";
      }
    }
  }

  function openReportModal(report) {
    if (!reportDetailDialog || !report) return;
    activeModalReport = report;

    if (detailFeedback) detailFeedback.textContent = "";

    const host = report.hostname || report.registeredDomain || "Report";
    if (reportDetailModalTitle) {
      reportDetailModalTitle.textContent = `${host} Analysis`;
    }

    const badgeLabel = getRiskBadgeLabel(report.riskLevel);
    const analysis = report.analysisData || {};
    const facts = analysis.facts || [
      { label: "Destination Host", value: report.hostname },
      { label: "Registered Domain", value: report.registeredDomain },
      { label: "Recorded Risk", value: badgeLabel },
    ];
    const findings = analysis.findings || [];

    let factsHtml = "";
    facts.forEach((f) => {
      factsHtml += `<div class="modal-fact-item"><dt>${escapeHtml(f.label)}</dt><dd>${escapeHtml(f.value)}</dd></div>`;
    });

    let findingsHtml = "";
    if (findings.length === 0) {
      findingsHtml = `
        <div class="url-no-findings" style="margin-top: 12px;">
          <svg viewBox="0 0 20 20" fill="none" width="18" height="18" aria-hidden="true">
            <circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="1.5" />
            <path d="m6.5 10 2.5 2.5 4.5-5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
          <span>No obvious structural red flags detected in the checks performed.</span>
        </div>
      `;
    } else {
      findingsHtml = '<ul class="url-findings-list" style="margin-top: 12px;">';
      findings.forEach((finding) => {
        findingsHtml += `
          <li class="url-finding-item" data-severity="${escapeHtml(finding.severity)}">
            <div class="url-finding-head">
              <h5 class="url-finding-title">${escapeHtml(finding.title)}</h5>
              <span class="url-finding-severity">${escapeHtml(finding.severity)}</span>
            </div>
            <p class="url-finding-explanation">${escapeHtml(finding.explanation)}</p>
            <p class="url-finding-matters"><strong>Why it matters:</strong> ${escapeHtml(finding.whyItMatters)}</p>
          </li>
        `;
      });
      findingsHtml += "</ul>";
    }

    const savedAtFormatted = formatDisplayDate(report.createdAt);

    if (reportDetailBody) {
      reportDetailBody.innerHTML = `
        <div class="url-verdict-card" data-verdict="${escapeHtml(report.riskLevel || "clean")}">
          <div class="verdict-header">
            <div>
              <p class="verdict-level-kicker">${escapeHtml(badgeLabel)}</p>
              <h4 class="verdict-title">${escapeHtml(report.verdictTitle || "Security Assessment")}</h4>
            </div>
            <span class="verdict-badge">${escapeHtml(badgeLabel)}</span>
          </div>
          <p class="verdict-summary">${escapeHtml(report.verdictSummary || "")}</p>
          <div class="verdict-meta">
            <span>Saved on: ${escapeHtml(savedAtFormatted)}</span>
            <span>•</span>
            <span>${report.findingsCount ?? findings.length} detected indicator${(report.findingsCount ?? findings.length) === 1 ? "" : "s"}</span>
          </div>
        </div>

        <div style="margin-top: 16px;">
          <label style="font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--ink-faint);">Redacted Target URL</label>
          <div class="report-detail-url-box">${escapeHtml(report.redactedUrl || report.url)}</div>
        </div>

        <div style="margin-top: 18px;">
          <h4 style="font-size: 0.95rem; margin-bottom: 8px;">Key Structural Facts</h4>
          <dl class="modal-facts-grid">${factsHtml}</dl>
        </div>

        <div style="margin-top: 18px;">
          <h4 style="font-size: 0.95rem; margin-bottom: 4px;">Detailed Findings &amp; Indicators</h4>
          ${findingsHtml}
        </div>

        <div class="url-disclaimer-box" style="margin-top: 18px;">
          <div class="disclaimer-title-row">
            <svg viewBox="0 0 20 20" fill="none" width="16" height="16" aria-hidden="true">
              <circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="1.5" />
              <path d="M10 9v5m0-8v1.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
            </svg>
            <strong>Heuristic Scope &amp; Privacy Notice</strong>
          </div>
          <p>
            This saved report records syntactic properties evaluated locally at scan time. It cannot guarantee a remote server’s safety, absence of malware, or ongoing reputation. Credentials and sensitive parameters were redacted prior to storage.
          </p>
        </div>
      `;
    }

    if (typeof reportDetailDialog.showModal === "function") {
      reportDetailDialog.showModal();
    } else {
      reportDetailDialog.setAttribute("open", "");
    }
  }

  function closeReportModal() {
    if (reportDetailDialog) {
      if (typeof reportDetailDialog.close === "function") {
        reportDetailDialog.close();
      } else {
        reportDetailDialog.removeAttribute("open");
      }
    }
    activeModalReport = null;
  }

  async function deleteReportById(reportId) {
    if (!reportId) return;
    const token = sessionStorage.getItem("ciphercheck_token");
    const headers = window.CipherCheckAuth?.getAuthHeaders() || {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };

    try {
      const res = await fetch(`/api/reports/${encodeURIComponent(reportId)}`, {
        method: "DELETE",
        headers,
        credentials: "include",
      });
      if (res.ok) {
        if (activeModalReport && activeModalReport.id === reportId) {
          closeReportModal();
        }
        await loadDashboardData(currentPage);
      } else {
        const data = await res.json();
        alert(data.error || "Failed to delete report.");
      }
    } catch (err) {
      alert("Network error while deleting report.");
    }
  }

  // Delegate click events inside reports list
  if (reportsList) {
    reportsList.addEventListener("click", (e) => {
      const inspectBtn = e.target.closest(".inspect-report-btn");
      if (inspectBtn) {
        const id = inspectBtn.getAttribute("data-id");
        const report = cachedReports.find((r) => r.id === id);
        if (report) {
          openReportModal(report);
        }
        return;
      }

      const delBtn = e.target.closest(".delete-report-btn");
      if (delBtn) {
        const id = delBtn.getAttribute("data-id");
        deleteReportById(id);
      }
    });
  }

  // Filter chips click
  filterChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      filterChips.forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      currentRiskFilter = chip.getAttribute("data-risk") || "all";
      currentPage = 1;
      loadDashboardData(1);
    });
  });

  // Search input debounced
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => {
        currentSearchQuery = e.target.value.trim();
        currentPage = 1;
        loadDashboardData(1);
      }, 250);
    });
  }

  // Refresh button
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      loadDashboardData(currentPage);
    });
  }

  // Pagination buttons
  if (prevPageBtn) {
    prevPageBtn.addEventListener("click", () => {
      if (currentPage > 1) {
        loadDashboardData(currentPage - 1);
      }
    });
  }
  if (nextPageBtn) {
    nextPageBtn.addEventListener("click", () => {
      loadDashboardData(currentPage + 1);
    });
  }

  // Detail Modal Actions
  if (reportDetailClose) {
    reportDetailClose.addEventListener("click", closeReportModal);
  }
  if (reportDetailDialog) {
    reportDetailDialog.addEventListener("click", (e) => {
      const rect = reportDetailDialog.getBoundingClientRect();
      const inDialog =
        rect.top <= e.clientY &&
        e.clientY <= rect.top + rect.height &&
        rect.left <= e.clientX &&
        e.clientX <= rect.left + rect.width;
      if (!inDialog) {
        closeReportModal();
      }
    });
  }

  if (copyDetailReportBtn) {
    copyDetailReportBtn.addEventListener("click", async () => {
      if (!activeModalReport) return;
      const text = [
        `CipherCheck Saved Security Scan Report`,
        `======================================`,
        `Hostname: ${activeModalReport.hostname || "Unknown"}`,
        `Registered Domain: ${activeModalReport.registeredDomain || "Unknown"}`,
        `Redacted URL: ${activeModalReport.redactedUrl || activeModalReport.url}`,
        `Recorded Risk: ${getRiskBadgeLabel(activeModalReport.riskLevel)}`,
        `Date Saved: ${formatDisplayDate(activeModalReport.createdAt)}`,
        `Verdict: ${activeModalReport.verdictTitle} - ${activeModalReport.verdictSummary}`,
        ``,
        `Indicators Detected (${activeModalReport.findingsCount}):`,
        ...(activeModalReport.analysisData?.findings || []).map(
          (f, idx) => `${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}\n   ${f.explanation}\n   Why it matters: ${f.whyItMatters}`
        ),
      ].join("\n");

      try {
        if (!navigator.clipboard || !navigator.clipboard.writeText) {
          throw new Error("Clipboard unavailable");
        }
        await navigator.clipboard.writeText(text);
        if (detailFeedback) {
          detailFeedback.textContent = "✓ Report copied to clipboard!";
          setTimeout(() => {
            if (detailFeedback.textContent.includes("✓ Report copied")) {
              detailFeedback.textContent = "";
            }
          }, 3000);
        }
      } catch (_) {
        if (detailFeedback) {
          detailFeedback.textContent = "Could not copy automatically.";
        }
      }
    });
  }

  if (deleteDetailReportBtn) {
    deleteDetailReportBtn.addEventListener("click", () => {
      if (!activeModalReport) return;
      deleteReportById(activeModalReport.id);
    });
  }

  // Clear History Modal & Action
  if (clearHistoryBtn && confirmClearDialog) {
    clearHistoryBtn.addEventListener("click", () => {
      if (typeof confirmClearDialog.showModal === "function") {
        confirmClearDialog.showModal();
      } else {
        confirmClearDialog.setAttribute("open", "");
      }
    });
  }

  const closeClearDialog = () => {
    if (confirmClearDialog) {
      if (typeof confirmClearDialog.close === "function") {
        confirmClearDialog.close();
      } else {
        confirmClearDialog.removeAttribute("open");
      }
    }
  };

  if (confirmClearClose) confirmClearClose.addEventListener("click", closeClearDialog);
  if (cancelClearBtn) cancelClearBtn.addEventListener("click", closeClearDialog);
  if (confirmClearDialog) {
    confirmClearDialog.addEventListener("click", (e) => {
      const rect = confirmClearDialog.getBoundingClientRect();
      const inDialog =
        rect.top <= e.clientY &&
        e.clientY <= rect.top + rect.height &&
        rect.left <= e.clientX &&
        e.clientX <= rect.left + rect.width;
      if (!inDialog) {
        closeClearDialog();
      }
    });
  }

  if (executeClearBtn) {
    executeClearBtn.addEventListener("click", async () => {
      executeClearBtn.disabled = true;
      executeClearBtn.textContent = "Clearing...";

      const token = sessionStorage.getItem("ciphercheck_token");
      const headers = window.CipherCheckAuth?.getAuthHeaders() || {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      };

      try {
        const res = await fetch("/api/reports", {
          method: "DELETE",
          headers,
          credentials: "include",
        });

        if (res.ok) {
          closeClearDialog();
          currentPage = 1;
          await loadDashboardData(1);
        } else {
          const data = await res.json();
          alert(data.error || "Failed to clear history.");
        }
      } catch (err) {
        alert("Connection error while clearing history.");
      } finally {
        executeClearBtn.disabled = false;
        executeClearBtn.textContent = "Yes, Clear All Reports";
      }
    });
  }

  // Guest sign-in button
  if (dashboardSignInBtn) {
    dashboardSignInBtn.addEventListener("click", () => {
      window.CipherCheckAuth?.openAuthModal();
    });
  }

  // Listen for auth state change
  window.addEventListener("ciphercheck:authchange", (e) => {
    const user = e.detail?.user;
    if (user) {
      currentPage = 1;
      loadDashboardData(1);
    } else {
      if (dashboardGuestCard) dashboardGuestCard.style.display = "flex";
      if (dashboardAuthContent) dashboardAuthContent.style.display = "none";
      updateSyncTag(false);
      renderStats({});
      if (reportsList) reportsList.innerHTML = "";
    }
  });

  // Listen for new report saved
  window.addEventListener("ciphercheck:reportschanged", () => {
    loadDashboardData(currentPage);
  });
}

// ============================================================================
// Tool 00: Personal Security Center & Actionable Security Recommendations
// ============================================================================

const SEVERITY_WEIGHT = {
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function generateSecurityRecommendations(options) {
  const opts = options && typeof options === "object" ? options : {};
  const {
    passwordAnalysis = null,
    urlAnalysis = null,
    savedReportsStats = null,
    savedReports = [],
    addressedIds = [],
    dismissedIds = [],
  } = opts;
  const recommendations = [];
  const addressedSet = new Set(Array.isArray(addressedIds) ? addressedIds.map(String) : []);
  const dismissedSet = new Set(Array.isArray(dismissedIds) ? dismissedIds.map(String) : []);

  // 1. Password Analysis Recommendations (based strictly on real analysis findings, no password text stored)
  if (passwordAnalysis && typeof passwordAnalysis === "object") {
    const score = Number(passwordAnalysis.score || 0);
    const length = Number(passwordAnalysis.length || 0);
    const findings = Array.isArray(passwordAnalysis.findings) ? passwordAnalysis.findings : [];
    const bandName =
      passwordAnalysis.band?.name ||
      (score < 20 ? "Very Weak" : score < 40 ? "Weak" : score < 65 ? "Fair" : score < 85 ? "Strong" : "Very Strong");

    // Weak / Low Entropy Password
    if (score < 40 && length > 0) {
      recommendations.push({
        id: "rec-password-entropy",
        title: "Strengthen Password Entropy",
        severity: "high",
        category: "password",
        explanation: `The analyzed password scored ${score}/100 (${bandName}). Passwords with low character length or limited variety are susceptible to rapid automated guessing attacks.`,
        actionLabel: "Generate 20+ Char Password",
        targetId: "generatorPanel",
      });
    }

    // Short length
    if (length > 0 && length < 12) {
      recommendations.push({
        id: "rec-password-length",
        title: "Extend Password Length to 16+ Characters",
        severity: "high",
        category: "password",
        explanation: `The analyzed password contains only ${length} character${length === 1 ? "" : "s"}. Length exponentially expands key space; increasing length beyond 16 characters provides exponential defense against brute-force recovery.`,
        actionLabel: "Generate Longer Password",
        targetId: "generatorPanel",
      });
    }

    // Weakness Patterns (sequential, repeated, dictionary words, keyboard runs)
    if (findings.length > 0) {
      const titles = findings.map((f) => f.title).filter(Boolean);
      const sampleTitles = titles.slice(0, 3).join(", ");
      recommendations.push({
        id: "rec-password-patterns",
        title: "Eliminate Predictable Password Patterns",
        severity: "medium",
        category: "password",
        explanation: `Detected structural patterns: ${sampleTitles || "predictable sequences"}. Password cracking algorithms test sequences, dictionary variations, and repeated character runs before brute-forcing.`,
        actionLabel: "Create Pattern-Free Password",
        targetId: "generatorPanel",
      });
    }

    // Strong password observed
    if (score >= 85) {
      recommendations.push({
        id: "rec-password-strong",
        title: "High-Entropy Password Verified",
        severity: "info",
        category: "password",
        explanation: `The analyzed password achieved ${score}/100 with high entropy and pattern resistance. Remember to use a unique password for each account and never reuse credentials across services.`,
        actionLabel: "Audit Another Password",
        targetId: "analyzerPanel",
      });
    }
  }

  // 2. URL Analysis Recommendations (grounded in actual observed indicators, honest disclaimers)
  if (urlAnalysis && typeof urlAnalysis === "object" && urlAnalysis.isValid) {
    const verdictLevel = String(urlAnalysis.verdict?.level || "").toLowerCase();
    const findings = Array.isArray(urlAnalysis.findings) ? urlAnalysis.findings : [];
    const host = urlAnalysis.urlParts?.hostname || "destination";

    if (verdictLevel === "high") {
      const findingTitles = findings.map((f) => f.title).filter(Boolean).slice(0, 2).join("; ");
      recommendations.push({
        id: "rec-url-high-risk",
        title: "Avoid Interacting with High-Risk Web Link",
        severity: "high",
        category: "url",
        explanation: `The evaluated link contains deceptive structural patterns: ${findingTitles || "High risk indicator"}. Do not enter login credentials, submit personal information, or approve security prompts on this address.`,
        actionLabel: "Inspect URL Findings",
        targetId: "urlPanel",
      });
    } else if (verdictLevel === "medium") {
      const findingTitles = findings.map((f) => f.title).filter(Boolean).slice(0, 2).join("; ");
      recommendations.push({
        id: "rec-url-medium-risk",
        title: "Exercise Caution with Flagged Web Address",
        severity: "medium",
        category: "url",
        explanation: `The analyzed URL for ${host} exhibits structural warning flags: ${findingTitles || "Structural anomalies"}. Confirm that the destination registered domain corresponds to the authentic service.`,
        actionLabel: "Review Link Facts",
        targetId: "urlPanel",
      });
    } else if (verdictLevel === "low") {
      const findingTitles = findings.map((f) => f.title).filter(Boolean).slice(0, 2).join("; ");
      recommendations.push({
        id: "rec-url-low-risk",
        title: "Review Minor Link Heuristic Notice",
        severity: "low",
        category: "url",
        explanation: `The analyzed URL for ${host} contains minor structural notes: ${findingTitles || "Minor heuristic flag"}. Confirm the destination before proceeding.`,
        actionLabel: "Review URL Details",
        targetId: "urlPanel",
      });
    } else if (verdictLevel === "clean") {
      recommendations.push({
        id: "rec-url-clean",
        title: "No Obvious Structural Red Flags Detected",
        severity: "info",
        category: "url",
        explanation: `Standard HTTPS structure observed for ${host}. Note that heuristic evaluation analyzes syntax locally and cannot verify server compromise or page content.`,
        actionLabel: "Analyze Another URL",
        targetId: "urlPanel",
      });
    }
  }

  // 3. Saved Reports History Aggregation Recommendations
  if (savedReportsStats && typeof savedReportsStats === "object") {
    const highCount = Number(savedReportsStats.high || 0);
    const mediumCount = Number(savedReportsStats.medium || 0);
    const totalCount = Number(savedReportsStats.total || 0);

    if (highCount > 0 || mediumCount > 1) {
      recommendations.push({
        id: "rec-history-flagged-links",
        title: "Review Elevated Link Risks in Saved Scans",
        severity: "medium",
        category: "history",
        explanation: `Your private scan history contains ${highCount} high-risk and ${mediumCount} elevated-risk links. Verify that suspicious addresses are not saved as browser bookmarks or trusted shortcuts.`,
        actionLabel: "Inspect Saved Scans",
        targetId: "dashboardPanel",
      });
    }

    if (
      Array.isArray(savedReports) &&
      savedReports.some(
        (r) =>
          r.url?.startsWith("http://") ||
          r.redactedUrl?.startsWith("http://") ||
          r.analysisData?.urlParts?.protocol === "http:",
      )
    ) {
      recommendations.push({
        id: "rec-history-unencrypted-http",
        title: "Avoid Unencrypted HTTP Links in Saved Scans",
        severity: "low",
        category: "history",
        explanation:
          "One or more saved scan reports address unencrypted (HTTP) destinations. Data in transit across plain HTTP can be inspected or altered by intermediate network devices.",
        actionLabel: "Filter HTTP Scans",
        targetId: "dashboardPanel",
      });
    }

    if (totalCount > 0 && highCount === 0 && mediumCount === 0) {
      recommendations.push({
        id: "rec-history-clean-profile",
        title: "Clean Structural Profile in Saved Scans",
        severity: "info",
        category: "history",
        explanation: `All ${totalCount} saved security scans exhibit standard web syntax with zero elevated-risk indicators. Continue auditing unfamiliar links prior to visiting.`,
        actionLabel: "View Saved History",
        targetId: "dashboardPanel",
      });
    }
  }

  // 4. Default / Hygiene Guides (present when specific tool analysis is not yet performed)
  if (!passwordAnalysis || passwordAnalysis.length === 0) {
    recommendations.push({
      id: "rec-guide-audit-password",
      title: "Audit Your Master Password Locally",
      severity: "info",
      category: "guide",
      explanation:
        "Evaluate your master password for length, repeated characters, dictionary words, and keyboard patterns. CipherCheck analyzes strictly in-browser without transmitting your password.",
      actionLabel: "Audit a Password",
      targetId: "analyzerPanel",
    });
  }

  if (!urlAnalysis || !urlAnalysis.isValid) {
    recommendations.push({
      id: "rec-guide-check-url",
      title: "Inspect Links Before Navigating",
      severity: "info",
      category: "guide",
      explanation:
        "Paste unfamiliar or suspicious web links into the risk checker to detect deceptive credentials, homoglyph characters, and raw IP hosts locally.",
      actionLabel: "Analyze a Web Link",
      targetId: "urlPanel",
    });
  }

  recommendations.push({
    id: "rec-guide-generate-password",
    title: "Generate Unique Cryptographic Passwords",
    severity: "info",
    category: "guide",
    explanation:
      "Create 20+ character passwords using the browser's Web Crypto API to ensure unique credentials across services and prevent credential-stuffing attacks.",
    actionLabel: "Generate Secure Password",
    targetId: "generatorPanel",
  });

  // Attach state: isAddressed, isDismissed
  const populated = recommendations.map((rec) => ({
    ...rec,
    isAddressed: addressedSet.has(rec.id),
    isDismissed: dismissedSet.has(rec.id),
  }));

  // Sort by priority:
  // 1. Unaddressed before Addressed
  // 2. Severity weight: high (4) > medium (3) > low (2) > info (1)
  // 3. Stable tie-break by ID
  populated.sort((a, b) => {
    if (a.isAddressed !== b.isAddressed) {
      return a.isAddressed ? 1 : -1;
    }
    const weightDiff = (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0);
    if (weightDiff !== 0) return weightDiff;
    return a.id.localeCompare(b.id);
  });

  return populated;
}

function initSecurityCenter() {
  const navBtnSecurityCenter = document.getElementById("navBtnSecurityCenter");
  const navBtnAnalyzer = document.getElementById("navBtnAnalyzer");
  const navBtnGenerator = document.getElementById("navBtnGenerator");
  const navBtnUrl = document.getElementById("navBtnUrl");
  const navBtnDashboard = document.getElementById("navBtnDashboard");
  const navBtnRecommendations = document.getElementById("navBtnRecommendations");
  const navRecsBadge = document.getElementById("navRecsBadge");

  const postureCardPassword = document.getElementById("postureCardPassword");
  const posturePasswordHeadline = document.getElementById("posturePasswordHeadline");
  const posturePasswordDetail = document.getElementById("posturePasswordDetail");

  const postureCardUrl = document.getElementById("postureCardUrl");
  const postureUrlHeadline = document.getElementById("postureUrlHeadline");
  const postureUrlDetail = document.getElementById("postureUrlDetail");

  const postureCardHistory = document.getElementById("postureCardHistory");
  const postureHistoryHeadline = document.getElementById("postureHistoryHeadline");
  const postureHistoryDetail = document.getElementById("postureHistoryDetail");

  const postureCardGuidance = document.getElementById("postureCardGuidance");
  const postureGuidanceHeadline = document.getElementById("postureGuidanceHeadline");
  const postureGuidanceDetail = document.getElementById("postureGuidanceDetail");

  const tabRecsActive = document.getElementById("tabRecsActive");
  const tabRecsAddressed = document.getElementById("tabRecsAddressed");
  const tabRecsDismissed = document.getElementById("tabRecsDismissed");
  const tabRecsAll = document.getElementById("tabRecsAll");
  const countRecsActive = document.getElementById("countRecsActive");
  const countRecsAddressed = document.getElementById("countRecsAddressed");
  const countRecsDismissed = document.getElementById("countRecsDismissed");
  const countRecsAll = document.getElementById("countRecsAll");

  const recommendationsList = document.getElementById("recommendationsList");
  const recsEmptyState = document.getElementById("recsEmptyState");
  const recsEmptyTitle = document.getElementById("recsEmptyTitle");
  const recsEmptyMessage = document.getElementById("recsEmptyMessage");
  const restoreRecsBtn = document.getElementById("restoreRecsBtn");
  const resetEmptyRecsBtn = document.getElementById("resetEmptyRecsBtn");

  let latestPasswordAnalysis = null;
  let latestUrlAnalysis = null;
  let latestSavedReportsStats = null;
  let latestSavedReports = [];

  let currentRecsFilter = "active"; // "active" | "addressed" | "dismissed" | "all"
  let addressedRecIds = new Set();
  let dismissedRecIds = new Set();

  function getRecStorageKey(userId) {
    return userId ? `ciphercheck_recs_${userId}` : "ciphercheck_recs_guest";
  }

  async function loadUserRecStatus() {
    const user = window.CipherCheckAuth?.getCurrentUser();
    const storageKey = getRecStorageKey(user?.id);
    let localData = { addressed: [], dismissed: [] };
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw) localData = JSON.parse(raw);
    } catch (_) {}

    if (user) {
      try {
        const headers = window.CipherCheckAuth?.getAuthHeaders() || {};
        const res = await fetch("/api/recommendations/status", {
          headers,
          credentials: "include",
        });
        if (res.ok) {
          const data = await res.json();
          const mergedAddressed = Array.from(new Set([...(data.addressed || []), ...(localData.addressed || [])]));
          const mergedDismissed = Array.from(new Set([...(data.dismissed || []), ...(localData.dismissed || [])]));
          localData = { addressed: mergedAddressed, dismissed: mergedDismissed };
          localStorage.setItem(storageKey, JSON.stringify(localData));
        }
      } catch (_) {}
    }

    addressedRecIds = new Set(localData.addressed || []);
    dismissedRecIds = new Set(localData.dismissed || []);
  }

  async function persistUserRecStatus() {
    const user = window.CipherCheckAuth?.getCurrentUser();
    const storageKey = getRecStorageKey(user?.id);
    const payload = {
      addressed: Array.from(addressedRecIds),
      dismissed: Array.from(dismissedRecIds),
    };

    try {
      localStorage.setItem(storageKey, JSON.stringify(payload));
    } catch (_) {}

    if (user) {
      try {
        const headers = window.CipherCheckAuth?.getAuthHeaders() || { "Content-Type": "application/json" };
        await fetch("/api/recommendations/status", {
          method: "POST",
          headers,
          credentials: "include",
          body: JSON.stringify(payload),
        });
      } catch (_) {}
    }
  }

  function updatePostureCards(allRecs) {
    // 1. Password Posture Card
    if (!latestPasswordAnalysis || latestPasswordAnalysis.length === 0) {
      if (postureCardPassword) postureCardPassword.dataset.state = "idle";
      if (posturePasswordHeadline) posturePasswordHeadline.textContent = "No Password Audited";
      if (posturePasswordDetail) {
        posturePasswordDetail.textContent = "Enter a password below to test length, entropy, and weakness factors.";
      }
    } else {
      const score = Number(latestPasswordAnalysis.score || 0);
      const bandName = latestPasswordAnalysis.band?.name || "Audited";
      const findingsCount = Array.isArray(latestPasswordAnalysis.findings) ? latestPasswordAnalysis.findings.length : 0;
      if (score < 40) {
        if (postureCardPassword) postureCardPassword.dataset.state = "risk";
        if (posturePasswordHeadline) posturePasswordHeadline.textContent = `${bandName} (${score}/100)`;
        if (posturePasswordDetail) {
          posturePasswordDetail.textContent = `${findingsCount} weakness factor${findingsCount === 1 ? "" : "s"} detected. High vulnerability.`;
        }
      } else if (score < 65) {
        if (postureCardPassword) postureCardPassword.dataset.state = "warning";
        if (posturePasswordHeadline) posturePasswordHeadline.textContent = `${bandName} (${score}/100)`;
        if (posturePasswordDetail) {
          posturePasswordDetail.textContent = "Moderate password resistance. Consider increasing length.";
        }
      } else {
        if (postureCardPassword) postureCardPassword.dataset.state = "good";
        if (posturePasswordHeadline) posturePasswordHeadline.textContent = `${bandName} (${score}/100)`;
        if (posturePasswordDetail) {
          posturePasswordDetail.textContent = "High entropy. Strong resistance to heuristic patterns.";
        }
      }
    }

    // 2. URL Posture Card
    if (!latestUrlAnalysis || !latestUrlAnalysis.isValid) {
      if (postureCardUrl) postureCardUrl.dataset.state = "idle";
      if (postureUrlHeadline) postureUrlHeadline.textContent = "No Link Analyzed";
      if (postureUrlDetail) {
        postureUrlDetail.textContent = "Paste a URL below to check for credential tricks, homoglyphs, and raw IP hosts.";
      }
    } else {
      const level = String(latestUrlAnalysis.verdict?.level || "clean").toLowerCase();
      const findingsCount = Array.isArray(latestUrlAnalysis.findings) ? latestUrlAnalysis.findings.length : 0;
      if (level === "high") {
        if (postureCardUrl) postureCardUrl.dataset.state = "risk";
        if (postureUrlHeadline) postureUrlHeadline.textContent = "High Risk Structure";
        if (postureUrlDetail) {
          postureUrlDetail.textContent = `Deceptive patterns detected (${findingsCount} indicator${findingsCount === 1 ? "" : "s"}).`;
        }
      } else if (level === "medium") {
        if (postureCardUrl) postureCardUrl.dataset.state = "warning";
        if (postureUrlHeadline) postureUrlHeadline.textContent = "Elevated Caution";
        if (postureUrlDetail) {
          postureUrlDetail.textContent = `Structural anomalies detected (${findingsCount} indicator${findingsCount === 1 ? "" : "s"}).`;
        }
      } else {
        if (postureCardUrl) postureCardUrl.dataset.state = "good";
        if (postureUrlHeadline) postureUrlHeadline.textContent = "No Red Flags";
        if (postureUrlDetail) {
          postureUrlDetail.textContent = "Standard HTTPS syntax observed. Zero structural anomalies.";
        }
      }
    }

    // 3. Saved Reports History Card
    const totalReports = Number(latestSavedReportsStats?.total || 0);
    const highReports = Number(latestSavedReportsStats?.high || 0);
    const mediumReports = Number(latestSavedReportsStats?.medium || 0);

    if (totalReports === 0) {
      if (postureCardHistory) postureCardHistory.dataset.state = "idle";
      if (postureHistoryHeadline) postureHistoryHeadline.textContent = "0 Saved Reports";
      if (postureHistoryDetail) {
        postureHistoryDetail.textContent = "Save URL assessments to monitor aggregate risk patterns across sessions.";
      }
    } else if (highReports > 0) {
      if (postureCardHistory) postureCardHistory.dataset.state = "risk";
      if (postureHistoryHeadline) postureHistoryHeadline.textContent = `${totalReports} Saved Report${totalReports === 1 ? "" : "s"}`;
      if (postureHistoryDetail) {
        postureHistoryDetail.textContent = `${highReports} high-risk scan${highReports === 1 ? "" : "s"} flagged in history.`;
      }
    } else if (mediumReports > 0) {
      if (postureCardHistory) postureCardHistory.dataset.state = "warning";
      if (postureHistoryHeadline) postureHistoryHeadline.textContent = `${totalReports} Saved Report${totalReports === 1 ? "" : "s"}`;
      if (postureHistoryDetail) {
        postureHistoryDetail.textContent = `${mediumReports} elevated-caution scan${mediumReports === 1 ? "" : "s"} in history.`;
      }
    } else {
      if (postureCardHistory) postureCardHistory.dataset.state = "good";
      if (postureHistoryHeadline) postureHistoryHeadline.textContent = `${totalReports} Saved Report${totalReports === 1 ? "" : "s"}`;
      if (postureHistoryDetail) {
        postureHistoryDetail.textContent = "Clean structural profile across all saved scan history.";
      }
    }

    // 4. Actionable Advice Card
    const activeCount = allRecs.filter((r) => !r.isDismissed && !r.isAddressed).length;
    if (postureGuidanceHeadline) {
      postureGuidanceHeadline.textContent = `${activeCount} Recommendation${activeCount === 1 ? "" : "s"}`;
    }
    if (postureGuidanceDetail) {
      postureGuidanceDetail.textContent =
        activeCount === 0
          ? "All active recommendations addressed. Great job maintaining strong security hygiene!"
          : "Prioritized steps derived from local analysis and security hygiene practices.";
    }
    if (navRecsBadge) {
      navRecsBadge.textContent = activeCount;
      navRecsBadge.style.display = activeCount > 0 ? "inline-flex" : "none";
    }
  }

  function getCategoryLabel(cat) {
    switch (cat) {
      case "password":
        return "Password Auditor";
      case "url":
        return "Link Risk Checker";
      case "history":
        return "Scan History";
      case "guide":
      default:
        return "Security Hygiene";
    }
  }

  function getSeverityBadge(severity) {
    switch (severity) {
      case "high":
        return '<span class="rec-severity-badge severity-high">High Priority</span>';
      case "medium":
        return '<span class="rec-severity-badge severity-medium">Elevated Caution</span>';
      case "low":
        return '<span class="rec-severity-badge severity-low">Low Concern</span>';
      case "info":
      default:
        return '<span class="rec-severity-badge severity-info">Security Guidance</span>';
    }
  }

  function renderRecommendations() {
    const allRecs = generateSecurityRecommendations({
      passwordAnalysis: latestPasswordAnalysis,
      urlAnalysis: latestUrlAnalysis,
      savedReportsStats: latestSavedReportsStats,
      savedReports: latestSavedReports,
      addressedIds: Array.from(addressedRecIds),
      dismissedIds: Array.from(dismissedRecIds),
    });

    updatePostureCards(allRecs);

    const activeRecs = allRecs.filter((r) => !r.isDismissed && !r.isAddressed);
    const addressedRecs = allRecs.filter((r) => !r.isDismissed && r.isAddressed);
    const dismissedRecs = allRecs.filter((r) => r.isDismissed);

    if (countRecsActive) countRecsActive.textContent = activeRecs.length;
    if (countRecsAddressed) countRecsAddressed.textContent = addressedRecs.length;
    if (countRecsDismissed) countRecsDismissed.textContent = dismissedRecs.length;
    if (countRecsAll) countRecsAll.textContent = allRecs.length;

    let displayList = [];
    if (currentRecsFilter === "active") {
      displayList = activeRecs;
    } else if (currentRecsFilter === "addressed") {
      displayList = addressedRecs;
    } else if (currentRecsFilter === "dismissed") {
      displayList = dismissedRecs;
    } else {
      displayList = allRecs;
    }

    if (!recommendationsList) return;
    recommendationsList.innerHTML = "";

    if (displayList.length === 0) {
      if (recsEmptyState) {
        recsEmptyState.style.display = "block";
        if (currentRecsFilter === "active") {
          if (recsEmptyTitle) recsEmptyTitle.textContent = "All Active Recommendations Addressed";
          if (recsEmptyMessage) {
            recsEmptyMessage.textContent =
              "You have addressed all active security recommendations in this view. As you evaluate new passwords or analyze web links, fresh actionable guidance will appear here automatically.";
          }
        } else if (currentRecsFilter === "addressed") {
          if (recsEmptyTitle) recsEmptyTitle.textContent = "No Addressed Recommendations Yet";
          if (recsEmptyMessage) {
            recsEmptyMessage.textContent =
              "When you take action on recommendations, mark them as addressed to track your security progress.";
          }
        } else if (currentRecsFilter === "dismissed") {
          if (recsEmptyTitle) recsEmptyTitle.textContent = "No Dismissed Recommendations";
          if (recsEmptyMessage) {
            recsEmptyMessage.textContent = "Any recommendations you dismiss from your active list will be archived here.";
          }
        } else {
          if (recsEmptyTitle) recsEmptyTitle.textContent = "No Recommendations Available";
          if (recsEmptyMessage) {
            recsEmptyMessage.textContent = "Use the tools below to audit passwords and analyze links for automated security guidance.";
          }
        }
      }
      return;
    }

    if (recsEmptyState) recsEmptyState.style.display = "none";

    displayList.forEach((rec) => {
      const li = document.createElement("li");
      li.className = `recommendation-item ${rec.isAddressed ? "is-addressed" : ""}`;
      li.setAttribute("data-id", rec.id);
      li.setAttribute("data-severity", rec.severity);

      const categoryLabel = getCategoryLabel(rec.category);
      const severityHtml = getSeverityBadge(rec.severity);

      li.innerHTML = `
        <div class="rec-top-row">
          <div class="rec-title-wrap">
            <span class="rec-category-tag">${escapeHtml(categoryLabel)}</span>
            <h4 class="rec-title">${escapeHtml(rec.title)}</h4>
          </div>
          <div>${severityHtml}</div>
        </div>
        <p class="rec-explanation">${escapeHtml(rec.explanation)}</p>
        <div class="rec-footer">
          <button class="button rec-action-btn" type="button" data-action="${escapeHtml(rec.id)}" data-target="${escapeHtml(rec.targetId)}">
            <svg viewBox="0 0 20 20" fill="none" width="14" height="14" aria-hidden="true">
              <path d="M4 10h11m-4.5-4.5L15 10l-4.5 4.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
            <span>${escapeHtml(rec.actionLabel)}</span>
          </button>
          <div class="rec-controls">
            <button class="button rec-addressed-btn ${rec.isAddressed ? "is-active" : ""}" type="button" data-rec-id="${escapeHtml(rec.id)}" aria-pressed="${rec.isAddressed}">
              ${rec.isAddressed ? "✓ Addressed" : "Mark Addressed"}
            </button>
            <button class="button rec-dismiss-btn" type="button" data-rec-id="${escapeHtml(rec.id)}" title="Dismiss recommendation" aria-label="Dismiss recommendation: ${escapeHtml(rec.title)}">
              ${rec.isDismissed ? "Restore" : "✕ Dismiss"}
            </button>
          </div>
        </div>
      `;

      // Wire action button
      const actionBtn = li.querySelector(".rec-action-btn");
      if (actionBtn) {
        actionBtn.addEventListener("click", () => {
          handleRecAction(rec);
        });
      }

      // Wire addressed toggle
      const addressedBtn = li.querySelector(".rec-addressed-btn");
      if (addressedBtn) {
        addressedBtn.addEventListener("click", () => {
          toggleAddressedRec(rec.id);
        });
      }

      // Wire dismiss button
      const dismissBtn = li.querySelector(".rec-dismiss-btn");
      if (dismissBtn) {
        dismissBtn.addEventListener("click", () => {
          toggleDismissRec(rec.id);
        });
      }

      recommendationsList.appendChild(li);
    });
  }

  function handleRecAction(rec) {
    const targetEl = document.getElementById(rec.targetId);
    if (!targetEl) return;

    targetEl.scrollIntoView({ behavior: "smooth", block: "start" });

    if (rec.targetId === "generatorPanel") {
      const lengthInput = document.getElementById("lengthInput");
      const generateButton = document.getElementById("generateButton");
      const generatedPassword = document.getElementById("generatedPassword");
      if (lengthInput && Number(lengthInput.value) < 20) {
        lengthInput.value = "20";
      }
      if (generateButton) {
        generateButton.click();
      }
      if (generatedPassword) {
        setTimeout(() => generatedPassword.focus(), 400);
      }
    } else if (rec.targetId === "analyzerPanel") {
      const passwordInput = document.getElementById("passwordInput");
      if (passwordInput) {
        setTimeout(() => passwordInput.focus(), 400);
      }
    } else if (rec.targetId === "urlPanel") {
      const urlInput = document.getElementById("urlInput");
      if (urlInput) {
        setTimeout(() => urlInput.focus(), 400);
      }
    } else if (rec.targetId === "dashboardPanel") {
      const searchInput = document.getElementById("dashboardSearchInput");
      if (searchInput) {
        setTimeout(() => searchInput.focus(), 400);
      }
    }
  }

  function toggleAddressedRec(id) {
    if (addressedRecIds.has(id)) {
      addressedRecIds.delete(id);
    } else {
      addressedRecIds.add(id);
      dismissedRecIds.delete(id);
    }
    persistUserRecStatus();
    renderRecommendations();
  }

  function toggleDismissRec(id) {
    if (dismissedRecIds.has(id)) {
      dismissedRecIds.delete(id);
    } else {
      dismissedRecIds.add(id);
      addressedRecIds.delete(id);
    }
    persistUserRecStatus();
    renderRecommendations();
  }

  function restoreAllRecs() {
    addressedRecIds.clear();
    dismissedRecIds.clear();
    persistUserRecStatus();
    renderRecommendations();
  }

  // Setup navigation smooth scroll & active tracking
  const navBtns = [
    { btn: navBtnSecurityCenter, target: "securityCenterPanel" },
    { btn: navBtnAnalyzer, target: "analyzerPanel" },
    { btn: navBtnGenerator, target: "generatorPanel" },
    { btn: navBtnUrl, target: "urlPanel" },
    { btn: navBtnDashboard, target: "dashboardPanel" },
    { btn: navBtnRecommendations, target: "recommendationsSection" },
  ];

  function navigateTo(target, updateHistory = true) {
    const el = document.getElementById(target);
    if (!el) return;
    const prefersReduced =
      typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    el.scrollIntoView({ behavior: prefersReduced ? "auto" : "smooth", block: "start" });
    if (updateHistory && typeof window !== "undefined" && window.history && window.history.pushState) {
      window.history.pushState(null, "", `#${target}`);
    }
    navBtns.forEach((item) => {
      if (item.target === target) {
        item.btn?.classList.add("active");
        item.btn?.setAttribute("aria-selected", "true");
      } else {
        item.btn?.classList.remove("active");
        item.btn?.setAttribute("aria-selected", "false");
      }
    });

    if (target === "analyzerPanel") {
      setTimeout(() => document.getElementById("passwordInput")?.focus(), 250);
    } else if (target === "generatorPanel") {
      setTimeout(() => document.getElementById("lengthInput")?.focus(), 250);
    } else if (target === "urlPanel") {
      setTimeout(() => document.getElementById("urlInput")?.focus(), 250);
    } else if (target === "dashboardPanel") {
      setTimeout(() => document.getElementById("dashboardSearchInput")?.focus(), 250);
    }
  }

  navBtns.forEach(({ btn, target }) => {
    if (!btn) return;
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      navigateTo(target, true);
    });
  });

  // Enable direct keyboard & touch interaction on posture summary cards
  const postureCardMap = [
    { card: postureCardPassword, target: "analyzerPanel" },
    { card: postureCardUrl, target: "urlPanel" },
    { card: postureCardHistory, target: "dashboardPanel" },
    { card: postureCardGuidance, target: "recommendationsSection" },
  ];

  postureCardMap.forEach(({ card, target }) => {
    if (!card) return;
    card.addEventListener("click", () => navigateTo(target, true));
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        navigateTo(target, true);
      }
    });
  });

  // Support direct deep linking on load and browser back/forward history navigation
  if (typeof window !== "undefined") {
    const initialHash = (window.location.hash || "").replace(/^#/, "");
    if (initialHash && document.getElementById(initialHash)) {
      setTimeout(() => navigateTo(initialHash, false), 100);
    }
    window.addEventListener("hashchange", () => {
      const currentHash = (window.location.hash || "").replace(/^#/, "");
      if (currentHash && document.getElementById(currentHash)) {
        navigateTo(currentHash, false);
      }
    });
  }

  // Keyboard navigation on tool tabs (ArrowLeft / ArrowRight)
  const navWrap = document.querySelector(".nav-links-wrap");
  if (navWrap) {
    navWrap.addEventListener("keydown", (e) => {
      const activeBtns = navBtns.map((n) => n.btn).filter(Boolean);
      const currentIndex = activeBtns.indexOf(document.activeElement);
      if (currentIndex === -1) return;
      if (e.key === "ArrowRight") {
        e.preventDefault();
        const nextIndex = (currentIndex + 1) % activeBtns.length;
        activeBtns[nextIndex].focus();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        const prevIndex = (currentIndex - 1 + activeBtns.length) % activeBtns.length;
        activeBtns[prevIndex].focus();
      }
    });
  }

  if (typeof window !== "undefined" && "IntersectionObserver" in window) {
    const navObserver = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const id = entry.target.id;
            navBtns.forEach((item) => {
              if (item.target === id) {
                item.btn?.classList.add("active");
                item.btn?.setAttribute("aria-selected", "true");
              } else {
                item.btn?.classList.remove("active");
                item.btn?.setAttribute("aria-selected", "false");
              }
            });
          }
        });
      },
      { rootMargin: "-20% 0px -60% 0px", threshold: 0.1 }
    );

    navBtns.forEach(({ target }) => {
      const el = document.getElementById(target);
      if (el) navObserver.observe(el);
    });
  }

  // Setup recommendation filter tabs
  const filterTabs = [
    { tab: tabRecsActive, filter: "active" },
    { tab: tabRecsAddressed, filter: "addressed" },
    { tab: tabRecsDismissed, filter: "dismissed" },
    { tab: tabRecsAll, filter: "all" },
  ];

  filterTabs.forEach(({ tab, filter }) => {
    if (!tab) return;
    tab.addEventListener("click", () => {
      filterTabs.forEach((item) => {
        item.tab?.classList.remove("active");
        item.tab?.setAttribute("aria-selected", "false");
      });
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");
      currentRecsFilter = filter;
      renderRecommendations();
    });
  });

  if (restoreRecsBtn) restoreRecsBtn.addEventListener("click", restoreAllRecs);
  if (resetEmptyRecsBtn) resetEmptyRecsBtn.addEventListener("click", restoreAllRecs);

  // Listen for analysis events from other tools
  window.addEventListener("ciphercheck:passwordanalysis", (e) => {
    latestPasswordAnalysis = e.detail?.analysis || null;
    renderRecommendations();
  });

  window.addEventListener("ciphercheck:urlanalysis", (e) => {
    latestUrlAnalysis = e.detail?.analysis || null;
    renderRecommendations();
  });

  window.addEventListener("ciphercheck:reportsloaded", (e) => {
    latestSavedReportsStats = e.detail?.stats || null;
    latestSavedReports = e.detail?.reports || [];
    renderRecommendations();
  });

  window.addEventListener("ciphercheck:authchange", async () => {
    await loadUserRecStatus();
    renderRecommendations();
  });

  // Initial load
  loadUserRecStatus().then(() => {
    renderRecommendations();
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initThemeToggle();
  initAnalyzer();
  initGenerator();
  initAuth();
  initUrlChecker();
  initSecurityDashboard();
  initSecurityCenter();
});



