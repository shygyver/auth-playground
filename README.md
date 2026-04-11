# auth-playground
A playground monorepo featuring various authorization server implementations.

---

## Structure

```
/apps
  /oidc-app
```

---

## Getting Started

### 1. Install dependencies

```bash
bun install
```

If the installation fails (or seems to be stuck), try clearing the cache and installing again:

```bash
bun pm cache rm
bun install
```

### 2. Run a specific app

```bash
bun run dev:oidc-app
```

Replace `oidc-app` with the name of the app you want to run.