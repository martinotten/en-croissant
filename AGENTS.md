# AGENTS.md – Repository Guidelines

## Build & Run
- `pnpm start-vite` (Vite dev), `pnpm dev` (full Tauri), `pnpm build` (prod bundle), `pnpm build-vite` (type‑check + Vite build), `pnpm format` (Biome format src/)

## Tests
- `pnpm test` (all), `pnpm test -- <path>.spec.ts` (single, e.g. `src/utils/tests/chess.test.ts`), `pnpm test --watch`

### Rust tests
- Run all Rust tests (backend / tauri):
  - `cargo test --manifest-path src-tauri/Cargo.toml`
- Run a single Rust test:
  - `cargo test --manifest-path src-tauri/Cargo.toml <testname> -- --nocapture`
- Run a single test with full backtrace (useful for panics):
  - `RUST_BACKTRACE=1 cargo test --manifest-path src-tauri/Cargo.toml <testname> -- --nocapture`
- When debugging failing tests:
  - Prefer running single tests with `--nocapture` to see stdout/println.
  - Add logging or guard unwraps and make 1–2 small attempts at fixing before escalating.
  - Convert temporary `println!` debugging to `log::debug!` before committing.

## Linting
- `pnpm lint` (TS + Biome), `pnpm lint:ci` (CI‑only errors), `pnpm lint:fix` (auto‑fix)
- Rust style/linting:
  - `cargo fmt` to format Rust code.
  - `cargo clippy -- -D warnings` to surface lint issues (optional; useful in CI).
  - Prefer `log::debug!` over `println!` for runtime debug messages.

## Style (Biome)
- 2‑space indent, LF, 80 char width; imports via `@/` alias (third‑party then internal); components `PascalCase`, hooks/utilities `camelCase`.
- No non‑null `!`, avoid `any`, no array‑index keys (lint warns); prefer `const`, arrow functions, trailing commas; use `@badrap/result` for error handling.
  
*No .cursor or Copilot rule files in this repo.*
