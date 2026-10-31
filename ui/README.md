# ShadowLens UI

Plain HTML, CSS and ES modules. No framework, no npm, no build step.

## Run

- Backend: `python -m shadowlens`, then open http://127.0.0.1:8787 (FastAPI serves this folder at `/`).
- Without the backend: `python3 -m http.server 8000 --directory ui`, then open http://localhost:8000/?mock=1
- Components sheet (Phase 1): `/components.html`
- ES modules do not load from `file://`; always use one of the servers above.

## Layout

- `app.css`: design tokens and shared components.
- `fonts/`: Hanken Grotesk and IBM Plex Mono (woff2, latin subset), self-hosted. No external requests.
- `js/api.js`: the only code that calls the backend. `?mock=1` reads `mock/*.json`.
- `js/store.js`: shared data topics. `js/ui.js`: DOM and format helpers (no `innerHTML`).
- `js/components/primitives.js`: buttons, toggle, chips, severity mark, state cell, coverage band, toast and more.

## Third-party

| Item | Licence |
| :-- | :-- |
| Hanken Grotesk (fonts/) | SIL Open Font License 1.1, see `fonts/LICENSE-HankenGrotesk-OFL.txt` |
| IBM Plex Mono (fonts/) | SIL Open Font License 1.1, see `fonts/LICENSE-IBMPlexMono-OFL.txt` |
