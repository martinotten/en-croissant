# AGENTS.md – Repository Guidelines

## Build & Run
- `pnpm start-vite` (Vite dev), `pnpm dev` (full Tauri), `pnpm build` (prod bundle), `pnpm build-vite` (type‑check + Vite build), `pnpm format` (Biome format src/)

## Tests
- `pnpm test` (all), `pnpm test -- <path>.spec.ts` (single, e.g. `src/utils/tests/chess.test.ts`), `pnpm test --watch`

## Linting
- `pnpm lint` (TS + Biome), `pnpm lint:ci` (CI‑only errors), `pnpm lint:fix` (auto‑fix)

## Style (Biome)
- 2‑space indent, LF, 80 char width; imports via `@/` alias (third‑party then internal); components `PascalCase`, hooks/utilities `camelCase`.
- No non‑null `!`, avoid `any`, no array‑index keys (lint warns); prefer `const`, arrow functions, trailing commas; use `@badrap/result` for error handling.

*No .cursor or Copilot rule files in this repo.*
