# auth-playground
A playground monorepo featuring various authorization server implementations.

---

## Features

- Multiple **apps** in one monorepo
- Written in **TypeScript** with project references
- Managed with **bun**
- Shared tsconfig

---

## Structure

```
/apps
  /oidc-app
  /oidc-persistent-app
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

Replace `oidc-app` with the name of the app you want to run (e.g., `oidc-persistent-app`).

### 3. Using nix

If you have Nix installed, you can drop into a fully configured development shell without manually installing Bun or other system dependencies.

```bash
nix develop --extra-experimental-features "nix-command flakes"
```

Once the shell is active, you can proceed with `bun install` and start developing.

---

## License

MIT