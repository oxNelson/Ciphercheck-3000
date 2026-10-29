# CipherCheck

A static, browser-only password auditor and Web Crypto password generator.

## Run & Operate

- The `CipherCheck preview` workflow serves `ciphercheck/` as static files on port 8000.
- To run the preview manually from the repository root: `python3 -m http.server 8000 --bind 0.0.0.0 --directory ciphercheck`
- Netlify: base directory `ciphercheck`, no build command, publish directory `.`
- No environment variables or package installation are required for the app.

## Stack

- App: HTML5, CSS3, vanilla JavaScript, and browser Web Crypto API.
- Static files only; the app does not use the workspace API server, database, authentication, frameworks, build tools, or external libraries.
- The repository's shared pnpm/API files are workspace scaffolding and are not part of the CipherCheck app.

## Where things live

- `ciphercheck/index.html` — app structure
- `ciphercheck/style.css` — responsive styling
- `ciphercheck/script.js` — local password analysis and secure generator
- `ciphercheck/README.md` — scoring rules, detector limits, and Netlify setup

## Architecture decisions

- Password analysis and generation run only in the browser; entered passwords are not sent or saved.
- Strength labels come from documented, deterministic rules and are not attack probabilities or breach results.
- Netlify publishes the static `ciphercheck/` directory without a build step.

## Product

Users can inspect password length, character categories, repetition, sequences, common patterns, and repeated sequences; see a five-band rule-based classification; and generate and copy passwords with configurable character categories.

## User preferences

- The supplied SRS is authoritative. Do not add features or imply breach detection without a genuine integration.

## Gotchas

- Do not add a native form submission, network request, password persistence, backend, database, framework, build tool, or external dependency to the app.
- Use `crypto.getRandomValues()` for password generation; never use `Math.random()`.
- Clipboard access can be denied by the browser; preserve explicit failure feedback.

## Pointers

- See `ciphercheck/README.md` for the implemented rules, score thresholds, limitations, and Netlify configuration.
