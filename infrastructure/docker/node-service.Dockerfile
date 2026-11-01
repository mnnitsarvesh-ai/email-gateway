# syntax=docker/dockerfile:1.7
# One image recipe for every NestJS service and for the migration job.
#   docker build -f infrastructure/docker/node-service.Dockerfile --build-arg APP=api .
#   docker build ... --build-arg APP=database   (runs `prisma migrate deploy`)
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS base
# openssl is required by the Prisma query engine.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate
WORKDIR /repo

FROM base AS build
# Fetch dependencies from the lockfile alone so this layer survives source changes.
COPY pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm fetch
COPY . .
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --offline
# Declared after install so every service shares the cached dependency layer.
ARG APP
RUN pnpm turbo run build --filter="@email-gateway/${APP}..."
# Self-contained production bundle: the app, its workspace packages and prod dependencies only.
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm --filter="@email-gateway/${APP}" deploy --prod /out
# Generate the Prisma client inside the bundle when the app depends on the database package.
RUN if [ -d /out/node_modules/@email-gateway/database ] || [ "${APP}" = "database" ]; then \
      cd "$( [ "${APP}" = "database" ] && echo /out || echo /out/node_modules/@email-gateway/database )" \
      && node "$(node -p "require.resolve('prisma/build/index.js')")" generate; \
    fi

FROM ${NODE_IMAGE} AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /out ./
USER node
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "--enable-source-maps", "dist/main.js"]
