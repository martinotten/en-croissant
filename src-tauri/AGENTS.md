# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Frontend app (Vite + TypeScript). Components in `src/components`, hooks in `src/hooks`, utilities in `src/utils`, tests co‑located under `src/**/tests/`.
- `src-tauri/`: Tauri desktop layer (Rust) and configuration; commands and app metadata live here.
- `public/`: Static assets served by Vite (icons, images, manifest).

## Build, Test, and Development Commands
- `pnpm start-vite`: Run Vite dev server only (fast UI iteration).
- `pnpm dev`: Full Tauri dev (desktop shell + frontend).
- `pnpm build`: Production Tauri bundle.
- `pnpm build-vite`: Type‑check and build the frontend.
- `pnpm test` | `pnpm test -- <path>.spec.ts` | `--watch`: Run all, a single, or watch tests (e.g., `src/utils/tests/chess.test.ts`).
- `pnpm lint` | `lint:ci` | `lint:fix`: Lint all, CI‑strict, or auto‑fix.
- `pnpm format`: Format source with Biome.

## Coding Style & Naming Conventions
- Indent 2 spaces, LF line endings, ~80 char width.
- Imports via `@/` alias; order third‑party first, then internal.
- Components: `PascalCase`; hooks/utilities: `camelCase` (e.g., `useThing.ts`).
- Prefer `const`, arrow functions, trailing commas; avoid `any` and non‑null `!`.
- No array‑index React keys. Use `@badrap/result` for error handling.

## Testing Guidelines
- Test files: `*.test.ts` co‑located (e.g., `src/utils/tests/…`). Keep tests small and deterministic.
- Run locally with `pnpm test`; add `--watch` during development; target a file with `-- <path>.spec.ts`.
- Aim for meaningful coverage of modules and edge cases; prefer black‑box tests for public APIs.

## Commit & Pull Request Guidelines
- Commits: concise, imperative summaries; group related changes; reference issues (`#123`) when relevant.
- PRs: clear description, motivation, and scope; link issues; include screenshots for UI changes and reproduction steps.
- Before opening: run `pnpm lint`, `pnpm test`, and `pnpm format`.

## Security & Configuration Tips
- Do not commit secrets; use environment files and local overrides.
- Tauri configuration lives under `src-tauri/`; update app metadata/settings there.
- Please do not add `.cursor`/Copilot rule files to this repo.

