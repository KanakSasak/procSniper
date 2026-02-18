# procSniper Build Guide

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Go | 1.22+ | |
| CGO | enabled | Required by `bi-zone/etw` library |
| mingw-w64 (gcc) | any recent | CGO C compiler for Windows - must be on PATH |
| Node.js | 18+ | For frontend build |
| npm | 9+ | Comes with Node.js |
| Wails CLI | v2.11.0 | `go install github.com/wailsapp/wails/v2/cmd/wails@latest` |

**Verify CGO setup:**
```
go env CGO_ENABLED   # must be "1"
gcc --version        # must resolve (mingw-w64)
```

---

## Build Targets

### GUI (Wails desktop app)

```
wails build -tags gui
```

Output: `build/bin/procSniper-gui.exe`

### CLI (headless, no GUI)

```
go build -tags "!gui" .
```

Output: `procSniper.exe` in project root

### Frontend only (for debugging)

```
cd frontend
npm install
npm run build
```

Output: `cmd/gui/dist/`

### Development mode (hot-reload)

```
wails dev -tags gui
```

Opens the app with live frontend reloading. Backend changes require restart.

---

## Build Architecture & Gotchas

### Two main entry points via build tags

The project has two `main()` functions at the project root, selected by build tags:

| File | Build Tag | Purpose |
|------|-----------|---------|
| `main.go` | `windows && !gui` | CLI entry point |
| `main_gui.go` | `gui` | Wails GUI entry point |

**The `-tags gui` flag is mandatory for `wails build`.** Without it, Wails picks up the CLI `main.go`, which prints usage and exits with code 1 during binding generation.

### Frontend asset embedding

- Vite outputs to `cmd/gui/dist/` (configured in `frontend/vite.config.ts`)
- `main_gui.go` embeds `cmd/gui/dist` via `//go:embed all:cmd/gui/dist` and uses `fs.Sub()` to extract the subdirectory for Wails' asset server
- `cmd/gui/main.go` also exists as a standalone GUI entry point that embeds `dist` directly (relative to its own location) - this is an alternative build path, not used by `wails build`

### CGO is required

The `bi-zone/etw` library uses CGO for Windows ETW APIs. If CGO is disabled or gcc is missing, the Go build will fail with linker errors. Ensure mingw-w64 is installed and on PATH.

### Wails CLI vs go.mod version mismatch

You may see: `Warning: go.mod is using Wails '2.9.2' but the CLI is 'v2.11.0'`

This is harmless. To silence it, run:
```
wails build -tags gui -u
```
The `-u` flag updates go.mod to match the CLI version.

### Pre-existing test issue

`test/simulators/` contains two files with `func main()` which causes `go build ./...` or `go vet ./...` to fail on that package. This is unrelated to the GUI build. Work around it:
```
go build ./internal/... ./config/...
```

### Frontend npm install

If `node_modules/` is missing, `wails build` runs `npm install` automatically (configured in `wails.json` via `frontend:install`). For manual frontend builds, run `npm install` first.

---

## Quick Reference

```bash
# Full GUI build
wails build -tags gui

# CLI only
go build -tags "!gui" .

# Verify Go packages compile (skip test/simulators)
go build ./internal/... ./config/...

# Frontend type-check + build
cd frontend && npm run build

# Dev mode with hot-reload
wails dev -tags gui
```

---

## Output Locations

| Build | Output |
|-------|--------|
| GUI | `build/bin/procSniper-gui.exe` |
| CLI | `procSniper.exe` (project root) |
| Frontend assets | `cmd/gui/dist/` |
| Wails bindings | `frontend/src/wailsjs/` (auto-generated) |
| Runtime logs | `logs/` |
