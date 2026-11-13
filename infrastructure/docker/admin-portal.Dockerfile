# syntax=docker/dockerfile:1.7
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS build
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm fetch
COPY . .
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --offline
ENV NEXT_TELEMETRY_DISABLED=1
# The package build runs the OpenAPI drift check (docs/api/openapi.json is kept by .dockerignore),
# next build, and the assertion that no dev fixture code reached .next (design P7, P9).
RUN pnpm turbo run build --filter="@email-gateway/admin-portal..."

FROM ${NODE_IMAGE} AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends tini && rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3001
WORKDIR /app
COPY --from=build --chown=node:node /repo/apps/admin-portal/.next/standalone ./
# Static assets include the self-hosted fonts (fontsource woff2 files under static/media).
COPY --from=build --chown=node:node /repo/apps/admin-portal/.next/static ./apps/admin-portal/.next/static
USER node
EXPOSE 3001
# Same probe as Compose: the portal's own liveness route (no dependency on the api).
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3001/api/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "apps/admin-portal/server.js"]
