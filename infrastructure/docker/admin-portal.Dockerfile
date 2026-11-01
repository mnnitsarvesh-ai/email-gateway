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
RUN pnpm turbo run build --filter="@email-gateway/admin-portal..."

FROM ${NODE_IMAGE} AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends tini && rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3001
WORKDIR /app
COPY --from=build --chown=node:node /repo/apps/admin-portal/.next/standalone ./
COPY --from=build --chown=node:node /repo/apps/admin-portal/.next/static ./apps/admin-portal/.next/static
USER node
EXPOSE 3001
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "apps/admin-portal/server.js"]
