# CipherCheck — Password Security Auditor

CipherCheck is a static, client-side password auditor and generator. The app uses plain HTML, CSS, and JavaScript; it has no backend, database, framework, external library, or breach-checking integration.

## Run locally

From the repository root, run:

```sh
python3 -m http.server 8000 --bind 0.0.0.0 --directory ciphercheck
```

The development preview uses a static file server only; all app behavior runs in the browser. The generator uses `crypto.getRandomValues()` and should be used in a browser context that exposes the Web Crypto API.

The server is not part of the deployed application. Opening `index.html` directly also works for analysis, although clipboard access depends on browser permissions.

## Netlify

Connect the GitHub repository to Netlify and set:

- **Base directory:** `ciphercheck`
- **Build command:** leave blank
- **Publish directory:** `.`

The deployed site is the four files in this folder. No build step or environment variables are required.

## Privacy and scope

- Password analysis runs in the current browser tab.
- The app does not send the entered password to a server, store it, place it in local storage, or submit it in a URL.
- CipherCheck does not check breach databases and does not claim to detect compromised passwords.
- “No listed patterns detected” is not a guarantee that a password is safe.
- Analysis results are deterministic rule-based indicators, not a probability of an attack succeeding or an estimate of crack time.

## Analysis rules

### Score

The score is the sum of four components, capped at 100:

1. **Length (0–40):** 1–5 characters = 0; 6–7 = 6; 8–11 = 12; 12–15 = 27; 16–19 = 35; 20 or more = 40.
2. **Character categories (0–20):** 5 points each for uppercase letters, lowercase letters, digits, and non-alphanumeric symbols present.
3. **Character uniqueness (0–15):** rounded `unique characters ÷ total characters × 15`.
4. **Pattern resistance (0–25):** starts at 25, then subtracts each detected pattern penalty; this component cannot go below 0.

Pattern penalties are: sequential run = 25; common word/keyboard pattern = 25; four-or-more identical consecutive characters = 22; repeated multi-character sequence = 18; letters followed only by 1–6 digits = 15. Findings can overlap, so multiple supported rules may reduce this component.

Classification thresholds: **Very Weak** 0–19; **Weak** 20–39; **Fair** 40–64; **Strong** 65–84; **Very Strong** 85–100. An empty input has no assessment.

### Weakness detections

- **Sequential pattern:** at least three consecutive ASCII letters or digits in ascending or descending order, such as `abc`, `cba`, or `123`.
- **Common password pattern:** a case-insensitive occurrence of one of `password`, `admin`, `welcome`, `letmein`, `qwerty`, `iloveyou`, `monkey`, `dragon`, `football`, `secret`, `login`, `princess`, `sunshine`, `master`, `trustno1`, `abc123`, `changeme`, `default`, or `root`; or a forward/reverse occurrence of the keyboard fragments `qwerty`, `asdfgh`, or `zxcvbn`. Non-alphanumeric characters are removed before this check.
- **Excessive repetition:** the same character appears at least four times consecutively.
- **Repeated sequence:** a sequence of 2–8 characters containing at least two distinct characters immediately repeats, such as `abcabc`.
- **Predictable construction:** after removing non-alphanumeric characters, the password consists of at least three letters followed by 1–6 digits, such as `word123`.

Each finding is shown only when its stated rule matches, with an explanation and a recommendation. The rules are intentionally limited: they do not cover every weak password or password-guessing strategy.

## Password generator

The generator accepts lengths from 1 to 64 and lets users select uppercase letters, lowercase letters, digits, and symbols. It rejects configurations with no category selected or with fewer characters than selected categories. Each selected category contributes at least one character; the result is then shuffled using Web Crypto random values with rejection sampling to avoid modulo bias. `Math.random()` is not used.

Copying uses the browser Clipboard API. If clipboard access is unavailable or denied, the app reports the failure and leaves the generated value available for manual copying.
