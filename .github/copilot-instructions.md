# Copilot Instructions for bitcoin-keys-demo

## Project Overview
- **Purpose:** Interactive Bitcoin cryptography demo (key generation, encoding, address derivation) using React, Vite, and Spark UI.
- **Main UI:** `src/App.tsx` orchestrates tabs for Private Key, Public Key, Address, Mini Key, and Seed Phrase demos. Each tab is a page component in `src/components/`.
- **Key Logic:** Bitcoin cryptography and encoding/decoding logic is in `src/lib/bitcoin.ts` and related files. UI state is often shared via Spark's `useKV` hook for cross-tab persistence.

## Architecture & Patterns
- **Component Structure:**
  - UI pages: `src/components/*Page.tsx` (e.g., `PrivateKeyPage.tsx`)
  - UI primitives: `src/components/ui/` (Radix UI + custom)
  - Bitcoin logic: `src/lib/bitcoin.ts`, `bip86-verification.ts`, etc.
  - Shared state: Spark's `useKV` for persistent, cross-tab state
- **Styling:** Tailwind CSS (`src/main.css`, `tailwind.config.js`).
- **Icons:** Phosphor icons via `@phosphor-icons/react`.
- **Error Handling:** Each tab is wrapped in `BitcoinErrorBoundary` for isolated error recovery.
- **Vite Aliases:** Use `@/` for `src/` (see `vite.config.ts` and `tsconfig.json`).

## Developer Workflows
- **Start Dev Server:** `npm run dev` (Vite)
- **Build:** `npm run build` (TypeScript + Vite)
- **Lint:** `npm run lint`
- **Preview Build:** `npm run preview`
- **Port Kill (if needed):** `npm run kill` (kills process on port 5000)

## Project-Specific Conventions
- **State Sharing:** Use Spark's `useKV` for persistent state between tabs/pages.
- **Bitcoin Logic:** All cryptographic and encoding logic should go in `src/lib/bitcoin.ts` or similar files in `src/lib/`.
- **UI Composition:** Prefer composition of UI primitives from `src/components/ui/`.
- **No Backend:** All logic is client-side; no server or API calls.
- **Testing:** No explicit test framework present; manual testing via UI.

## Integration & Dependencies
- **Spark UI:** Uses `@github/spark` for hooks and Vite plugin.
- **Radix UI:** For accessible UI primitives.
- **bitcoinjs-lib, bip39, ecpair, bs58, tiny-secp256k1:** For Bitcoin cryptography.
- **Tailwind CSS:** For styling.

## Examples
- **Add a new Bitcoin demo:** Create a new `*Page.tsx` in `src/components/`, add to `App.tsx` tab list, use `useKV` for state if needed.
- **Add a new UI primitive:** Place in `src/components/ui/`, import and compose in page components.

## Key Files
- `src/App.tsx` — main UI and tab logic
- `src/components/PrivateKeyPage.tsx` — example of stateful, interactive Bitcoin logic
- `src/lib/bitcoin.ts` — core Bitcoin encoding/decoding logic
- `vite.config.ts`, `tsconfig.json` — alias and build config

---

For more, see `README.md` and code comments. When in doubt, follow the patterns in `src/components/` and `src/lib/`.
