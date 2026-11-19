# syntax=docker/dockerfile:1.7
# provider-fake (TEST-ONLY, step 8.2): the library's FakeProviderServer behind a small front
# server (infrastructure/provider-fake/server.mjs) with a DNS responder for relay-proof.test.
# Build context: the repository root, like infrastructure/docker/node-service.Dockerfile:
#   docker build -f infrastructure/provider-fake/Dockerfile -t email-gateway/provider-fake:local .
# Same node base image as every service; no other third-party image. The runtime holds only the
# compiled fake (dist/testing/fake-provider-server.js), its one dependency (jose) and the two
# .mjs files: no Prisma, no workspace packages, no secrets.
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS build
# openssl: the Prisma client generation of @email-gateway/database (a build dependency of the
# library) needs it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm fetch
COPY . .
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --offline
RUN pnpm turbo run build --filter="@email-gateway/provider-integrations..."
RUN mkdir -p /out/lib /out/node_modules \
 && cp packages/provider-integrations/dist/testing/fake-provider-server.js /out/lib/ \
 && cp -rL packages/provider-integrations/node_modules/jose /out/node_modules/jose \
 && cp infrastructure/provider-fake/server.mjs infrastructure/provider-fake/dns.mjs /out/

FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /out ./
USER node
EXPOSE 8480/tcp 5300/udp 5300/tcp
CMD ["node", "server.mjs"]
