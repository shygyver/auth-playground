# auth-playground
A playground monorepo featuring various authorization server implementations.

---

## Features

- Multiple **apps** in one monorepo
- Written in **TypeScript** with project references
- Managed with **bun**
- Shared utilities and configs (e.g. prettier, tsconfig)

---

## Structure

```
/apps
  /oidc-app
  /oidc-persistent-app
  /oidc-consent-app
  /oidc-refresh-app
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

### 4. Using Docker

Each app has its own Dockerfile for containerization. To build and run an app using Docker, follow these steps:
1. Build the Docker image for the desired app (replace `oidc-app` with the target app name):

   ```bash
   docker build -t oidc-app -f apps/oidc-app/Dockerfile .
   ```

2. Run the Docker container:

   ```bash
   docker run -p 3000:3000 oidc-app
   ```
   For apps that require environment variables (like `oidc-persistent-app`), you can pass them when running the container: 
   ```bash
   docker run -p 3001:3001 -e DATABASE_URL="your_database_url" -e MASTER_KEY="your_base64_encoded_master_key" oidc-persistent-app
   ```
   or create a `.env` file with the necessary variables and use the `--env-file` option:
   ```bash
   docker run -p 3001:3001 --env-file ./apps/oidc-persistent-app/.env oidc-persistent-app
   ```

### 5. Using Docker Compose

A `docker-compose.yml` file is provided for easier management of multiple services. To start a service defined in the compose file, run:

```bash
docker-compose up --build oidc-app
```
> Replace `oidc-app` with the name of the service you want to run (e.g., `oidc-persistent-app`).

For services that require environment variables, specify them directly in the `docker-compose.yml` file under the respective service or comment them out and provide a `.env` file with the necessary variables in the app's directory. Some default values are already set in the compose file for local development.

---

## License

MIT
