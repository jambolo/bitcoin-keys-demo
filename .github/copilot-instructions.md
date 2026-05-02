# Copilot Instructions for bitcoin-keys-demo

## Project Overview
- **Purpose:** Interactive Bitcoin cryptography demo (key generation, encoding, address derivation) using React, Vite, and Material UI.
- **Main UI:** `src/App.tsx` orchestrates tabs for Private Key, Public Key, Address, Mini Key, and Seed Phrase demos. Each tab is a page component in `src/components/`.
- **Key Logic:** Bitcoin cryptography and encoding/decoding logic is in `src/lib/bitcoin.ts` and related files. UI state is persisted via a localStorage-backed hook in `src/hooks/usePersistentKV.ts`.

## Architecture & Patterns
- **Component Structure:**
  - UI pages: `src/components/*Page.tsx` (e.g., `PrivateKeyPage.tsx`)
  - UI primitives: `src/components/ui/` (MUI-backed wrappers)
  - Bitcoin logic: `src/lib/bitcoin.ts`, `bip86-verification.ts`, etc.
  - Shared state: localStorage-backed `usePersistentKV` for persistent state
- **Styling:** Material UI theme (`ThemeProvider` in `src/main.tsx`) with existing CSS retained while migration continues.
- **Icons:** Phosphor icons via `@phosphor-icons/react`.
- **Error Handling:** Each tab is wrapped in `BitcoinErrorBoundary` for isolated error recovery.
- **Vite Aliases:** Use `@/` for `src/` (see `vite.config.ts` and `tsconfig.json`).

## Developer Workflows
- **Start Dev Server:** `pnpm dev` (Vite)
- **Build:** `pnpm build` (TypeScript + Vite)
- **Lint:** `pnpm lint`
- **Preview Build:** `pnpm preview`
- **Port Kill (if needed):** `pnpm kill` (kills process on port 5000)

## Project-Specific Conventions
- **State Sharing:** Use `usePersistentKV` for persistent state between tabs/pages.
- **Bitcoin Logic:** All cryptographic and encoding logic should go in `src/lib/bitcoin.ts` or similar files in `src/lib/`.
- **UI Composition:** Prefer composition using Material UI components.
- **No Backend:** All logic is client-side; no server or API calls.
- **Testing:** No explicit test framework present; manual testing via UI.

## Integration & Dependencies
- **Material UI:** Uses `@mui/material` with Emotion (`@emotion/react`, `@emotion/styled`).
- **bitcoinjs-lib, bip39, ecpair, bs58, tiny-secp256k1:** For Bitcoin cryptography.
- **Tailwind CSS:** Present during migration; remove once no longer used.

## Examples
- **Add a new Bitcoin demo:** Create a new `*Page.tsx` in `src/components/`, add to `App.tsx` tab list, use `usePersistentKV` for persisted inputs if needed.
- **Add a new UI primitive:** Place in `src/components/ui/`, preferring MUI-backed wrappers.

## Key Files
- `src/App.tsx` — main UI and tab logic
- `src/components/PrivateKeyPage.tsx` — example of stateful, interactive Bitcoin logic
- `src/lib/bitcoin.ts` — core Bitcoin encoding/decoding logic
- `vite.config.ts`, `tsconfig.json` — alias and build config

---

For more, see `README.md` and code comments. When in doubt, follow the patterns in `src/components/` and `src/lib/`.
