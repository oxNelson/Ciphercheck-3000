import { test, describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const scriptPath = path.join(__dirname, "..", "ciphercheck", "script.js");
const scriptContent = fs.readFileSync(scriptPath, "utf-8");

describe("Theme Toggle & Persistence", () => {
  test("Applies theme and updates DOM attributes and localStorage", () => {
    const store = new Map();
    const domAttrs = new Map();
    const metaAttrs = new Map();

    const sandbox = {
      document: {
        addEventListener: () => {},
        getElementById: (id) => {
          if (id === "themeToggle") {
            return {
              setAttribute: (k, v) => domAttrs.set(`toggle:${k}`, v),
            };
          }
          if (id === "themeLabel") {
            return {
              textContent: "",
            };
          }
          return null;
        },
        querySelectorAll: () => [],
        documentElement: {
          setAttribute: (k, v) => domAttrs.set(`root:${k}`, v),
          getAttribute: (k) => domAttrs.get(`root:${k}`),
        },
        querySelector: (sel) => {
          if (sel === 'meta[name="theme-color"]') {
            return {
              setAttribute: (k, v) => metaAttrs.set(k, v),
            };
          }
          return null;
        },
      },
      window: {
        matchMedia: () => ({ matches: false, addEventListener: () => {} }),
      },
      localStorage: {
        getItem: (k) => store.get(k) || null,
        setItem: (k, v) => store.set(k, v),
      },
      crypto: globalThis.crypto,
      console,
    };

    vm.createContext(sandbox);
    const exported = vm.runInContext(
      scriptContent +
        `\nvar __exported = { applyTheme, getStoredTheme, getSystemTheme }; __exported;`,
      sandbox
    );

    // Apply dark theme with user action = true
    exported.applyTheme("dark", true);
    assert.equal(domAttrs.get("root:data-theme"), "dark");
    assert.equal(store.get("ciphercheck-theme"), "dark");
    assert.equal(metaAttrs.get("content"), "#0f1411");

    // Apply light theme with user action = true
    exported.applyTheme("light", true);
    assert.equal(domAttrs.get("root:data-theme"), "light");
    assert.equal(store.get("ciphercheck-theme"), "light");
    assert.equal(metaAttrs.get("content"), "#f4f6f3");
  });
});
