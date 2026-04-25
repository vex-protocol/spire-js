# ── Build stage ──────────────────────────────────────────────────────────
FROM node:24-alpine AS build

# argon2 compiles native C code via node-gyp
RUN apk add --no-cache python3 make g++

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ── Runtime stage ────────────────────────────────────────────────────────
FROM node:24-alpine

# Healthcheck: deploy/spire-container-health.sh (Node + fetch; no extra apk packages)
RUN deluser --remove-home node \
 && addgroup -g 1000 spire && adduser -u 1000 -G spire -s /bin/sh -D spire

WORKDIR /app
COPY --from=build /build/node_modules ./node_modules
COPY package.json ./
COPY src ./src
RUN mkdir -p /app/deploy
COPY --chown=spire:spire deploy/resolve-spire-listen-port.sh \
    deploy/spire-container-health.sh \
    /app/deploy/
RUN chmod +x /app/deploy/resolve-spire-listen-port.sh /app/deploy/spire-container-health.sh

# /data is the writable volume for SQLite DB + uploaded files.
# Spire creates files/, avatars/, emoji/ relative to CWD.
RUN mkdir -p /data/files /data/avatars /data/emoji && chown -R spire:spire /data

USER spire
WORKDIR /data

ENV NODE_ENV=production

# Spire binds 16777 unless API_PORT; see src/spireListenPort.ts
EXPOSE 16777

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["/bin/sh", "/app/deploy/spire-container-health.sh"]

ENTRYPOINT ["node", "--experimental-strip-types", "/app/src/run.ts"]
