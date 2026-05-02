# --- Stage 1: Dependencies ---
FROM oven/bun:latest AS deps
WORKDIR /app

# Copy root config and lockfile
COPY package.json bun.lock ./
# Copy app package.json
COPY apps/oidc-app/package.json ./apps/oidc-app/

RUN bun install

# --- Stage 2: Builder ---
FROM oven/bun:latest AS builder
WORKDIR /app
COPY --from=deps /app/bun.lock ./bun.lock
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./package.json
COPY --from=deps /app/apps/oidc-app/node_modules ./apps/oidc-app/node_modules
COPY --from=deps /app/apps/oidc-app/package.json ./apps/oidc-app/package.json

# Copy all source code
COPY turbo.json ./
COPY tsconfig.json ./
COPY apps/oidc-app/tsconfig.json ./apps/oidc-app/tsconfig.json
COPY apps/oidc-app/src ./apps/oidc-app/src

RUN bun run build:oidc-app

# --- Stage 3: Runner ---
FROM oven/bun:alpine AS runner
WORKDIR /app

# Copy built app and node_modules
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/apps/oidc-app/node_modules ./apps/oidc-app/node_modules
COPY --from=builder /app/apps/oidc-app/dist ./apps/oidc-app/dist

WORKDIR /app/apps/oidc-app

USER bun
EXPOSE 3000

ENTRYPOINT ["bun", "dist"]
