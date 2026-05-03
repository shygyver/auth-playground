# --- Stage 1: Dependencies ---
FROM oven/bun:latest AS deps
WORKDIR /app

# Copy root config and lockfile
COPY package.json bun.lock ./
# Copy app package.json
COPY apps/oidc-refresh-app/package.json ./apps/oidc-refresh-app/

RUN bun install

# --- Stage 2: Builder ---
FROM oven/bun:latest AS builder
WORKDIR /app
COPY --from=deps /app/bun.lock ./bun.lock
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./package.json
COPY --from=deps /app/apps/oidc-refresh-app/node_modules ./apps/oidc-refresh-app/node_modules
COPY --from=deps /app/apps/oidc-refresh-app/package.json ./apps/oidc-refresh-app/package.json

# Copy all source code
COPY turbo.json ./
COPY tsconfig.json ./
COPY apps/oidc-refresh-app/tsconfig.json ./apps/oidc-refresh-app/tsconfig.json
COPY apps/oidc-refresh-app/src ./apps/oidc-refresh-app/src

RUN bun run build:oidc-refresh-app

# --- Stage 3: Runner ---
FROM oven/bun:alpine AS runner
WORKDIR /app

# Copy built app and node_modules
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/apps/oidc-refresh-app/node_modules ./apps/oidc-refresh-app/node_modules
COPY --from=builder /app/apps/oidc-refresh-app/dist ./apps/oidc-refresh-app/dist

WORKDIR /app/apps/oidc-refresh-app

USER bun
EXPOSE 3003

ENTRYPOINT ["bun", "dist"]
