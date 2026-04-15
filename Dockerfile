# ── Build stage ──────────────────────────────────────────────────────────
FROM node:24-alpine AS build

# argon2 compiles native C code via node-gyp
RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json vitest.config.ts ./
COPY src ./src

# ── CI target — stop here for testing (has devDeps) ─────────────────────
FROM build AS ci

# ── Production target — prune devDeps ────────────────────────────────────
FROM build AS prod-deps
RUN npm prune --omit=dev

FROM node:24-alpine

RUN deluser --remove-home node \
 && addgroup -g 1000 spire && adduser -u 1000 -G spire -s /bin/sh -D spire

WORKDIR /app
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/package.json ./
COPY --from=build /app/src ./src

# /data is the writable volume for SQLite DB + uploaded files.
# Spire creates files/, avatars/, emoji/ relative to CWD.
RUN mkdir -p /data/files /data/avatars /data/emoji && chown -R spire:spire /data

USER spire
WORKDIR /data

ENV NODE_ENV=production

EXPOSE 16777

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:16777/status || exit 1

ENTRYPOINT ["node", "--experimental-strip-types", "/app/src/run.ts"]
