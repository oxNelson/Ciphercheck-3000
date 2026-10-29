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
  console,
};

vm.createContext(sandbox);
const exported = vm.runInContext(
  scriptContent +
    `\nvar __exported = { analyzePassword, generateSecurePassword, lengthPoints, getStrengthBand }; __exported;`,
  sandbox
);

const { analyzePassword, generateSecurePassword, lengthPoints, getStrengthBand } =
  exported;

describe("CipherCheck Core Password Analyzer", () => {
  test("Length scoring follows documented rules", () => {
    assert.equal(lengthPoints(0), 0);
    assert.equal(lengthPoints(5), 0);
    assert.equal(lengthPoints(6), 6);
    assert.equal(lengthPoints(7), 6);
    assert.equal(lengthPoints(8), 12);
    assert.equal(lengthPoints(11), 12);
    assert.equal(lengthPoints(12), 27);
    assert.equal(lengthPoints(15), 27);
    assert.equal(lengthPoints(16), 35);
    assert.equal(lengthPoints(19), 35);
    assert.equal(lengthPoints(20), 40);
    assert.equal(lengthPoints(40), 40);
  });

  test("Score bands match classification requirements", () => {
    assert.equal(getStrengthBand(0).name, "Very Weak");
    assert.equal(getStrengthBand(19).name, "Very Weak");
    assert.equal(getStrengthBand(20).name, "Weak");
    assert.equal(getStrengthBand(39).name, "Weak");
    assert.equal(getStrengthBand(40).name, "Fair");
    assert.equal(getStrengthBand(64).name, "Fair");
    assert.equal(getStrengthBand(65).name, "Strong");
    assert.equal(getStrengthBand(84).name, "Strong");
    assert.equal(getStrengthBand(85).name, "Very Strong");
    assert.equal(getStrengthBand(100).name, "Very Strong");
  });

  test("Detects predictable numeric sequences", () => {
    const result = analyzePassword("12345678");
    assert.ok(result.findings.some((f) => f.id === "sequence"));
  });

  test("Detects common password patterns", () => {
    const result = analyzePassword("password123");
    assert.ok(result.findings.some((f) => f.id === "common"));
  });

  test("Detects excessive character repetition", () => {
    const result = analyzePassword("aaaaaaa!");
    assert.ok(result.findings.some((f) => f.id === "repetition"));
  });

  test("Detects repeated sequences", () => {
    const result = analyzePassword("abcabc!12");
    assert.ok(result.findings.some((f) => f.id === "repeatedSequence"));
  });

  test("Detects predictable construction (word followed by digits)", () => {
    const result = analyzePassword("secret12");
    assert.ok(result.findings.some((f) => f.id === "construction"));
  });

  test("High entropy, long password earns Very Strong without weakness findings", () => {
    const result = analyzePassword("k9$Xp#2mQ!vL9*wZ4@Rt");
    assert.equal(result.findings.length, 0);
    assert.ok(result.score >= 85);
    assert.equal(result.band.name, "Very Strong");
  });
});

describe("CipherCheck Secure Password Generator", () => {
  test("Generates password with exact requested length", () => {
    const categories = ["uppercase", "lowercase", "numbers", "symbols"];
    const password = generateSecurePassword(24, categories);
    assert.equal(password.length, 24);
  });

  test("Generated password contains all selected categories", () => {
    const categories = ["uppercase", "lowercase", "numbers", "symbols"];
    const password = generateSecurePassword(16, categories);
    assert.match(password, /[A-Z]/);
    assert.match(password, /[a-z]/);
    assert.match(password, /\d/);
    assert.match(password, /[^A-Za-z0-9]/);
  });

  test("Rejects invalid configuration where length is smaller than selected categories", () => {
    const categories = ["uppercase", "lowercase", "numbers", "symbols"];
    assert.throws(() => generateSecurePassword(3, categories), /too short/);
  });

  test("Rejects empty categories", () => {
    assert.throws(() => generateSecurePassword(12, []), /at least one/);
  });
});
