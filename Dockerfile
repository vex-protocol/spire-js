# ── Build stage ──────────────────────────────────────────────────────────
FROM node:24-alpine AS build

# argon2 compiles native C code via node-gyp
RUN apk add --no-cache python3 make g++

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ── Runtime stage ────────────────────────────────────────────────────────
FROM node:24-alpine

RUN deluser --remove-home node \
 && addgroup -g 1000 spire && adduser -u 1000 -G spire -s /bin/sh -D spire

WORKDIR /app
COPY --from=build /build/node_modules ./node_modules
COPY package.json ./
COPY src ./src

# /data is the writable volume for SQLite DB + uploaded files.
# Spire creates files/, avatars/, emoji/ relative to CWD.
RUN mkdir -p /data/files /data/avatars /data/emoji && chown -R spire:spire /data

USER spire
WORKDIR /data

ENV NODE_ENV=production

EXPOSE 16777

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:16777/healthz || exit 1

ENTRYPOINT ["node", "--experimental-strip-types", "/app/src/run.ts"]
