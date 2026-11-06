# syntax=docker/dockerfile:1.7
# Image of the isolated dynamic URL inspection (step 4.3 U15, ADR-0032): one image, two containers
#   url-browser-worker  node dist/main.js        (headless Chromium through the egress proxy)
#   url-egress-proxy    node dist/proxy-main.js  (authenticated SSRF-guarded forward proxy)
# chosen by the Compose / Kubernetes command. Build (one image at a time on the 8 GB VM):
#   docker build -f infrastructure/docker/url-browser-worker.Dockerfile .
# The build stage is node-service.Dockerfile's with APP=url-browser-worker. The runtime installs
# Playwright's `chromium-headless-shell` for EXACTLY the pinned playwright-core version (its own
# installer, `--with-deps` adds the Debian libraries), so browser and driver always match.
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate
WORKDIR /repo

FROM base AS build
COPY pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm fetch
COPY . .
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --offline
ARG APP=url-browser-worker
RUN pnpm turbo run build --filter="@email-gateway/${APP}..."
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm --filter="@email-gateway/${APP}" deploy --prod /out
# The worker imports @email-gateway/common (which depends on the database package): generate the
# Prisma client so the module graph loads, although the worker never connects to MySQL. The
# database package is a TRANSITIVE dependency here, so it lives under node_modules/.pnpm, not at
# /out/node_modules/@email-gateway/database (step 4.3 §12 WP4: found when the image first ran).
RUN db="$(find /out/node_modules/.pnpm -maxdepth 4 -type d -path '*/node_modules/@email-gateway/database' | head -n 1)" \
 && test -n "$db" \
 && cd "$db" \
 && node "$(node -p "require.resolve('prisma/build/index.js')")" generate

FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PLAYWRIGHT_SKIP_BROWSER_GC=1
WORKDIR /app
COPY --from=build --chown=node:node /out ./
# Headless shell + its OS dependencies for the pinned playwright-core (root, build time only),
# then tini. Nothing is downloaded at run time (the rootfs is read-only).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && node node_modules/playwright-core/cli.js install --with-deps --only-shell chromium \
 && rm -rf /var/lib/apt/lists/* /root/.cache \
 && chmod -R a+rX /ms-playwright
USER node
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "--enable-source-maps", "dist/main.js"]
