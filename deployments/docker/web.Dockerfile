# SecureOps dashboard.
#
# The dashboard consumes SecureOps domain models only; it never receives raw
# scanner output (CLAUDE.md §18).

FROM node:26-alpine AS deps
WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:26-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY apps/web ./
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:26-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Patch base-image OS packages, then remove the bundled npm CLI: the runtime
# only executes `node server.js`, so a package manager here is pure attack
# surface (and the npm bundle carries its own vendored dependencies).
RUN apk upgrade --no-cache && \
    rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/bin/npm /usr/local/bin/npx \
           /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg

# Next's standalone output already contains the trimmed node_modules it needs.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public

# Rule §15.10: containers run as non-root. The node image ships this user.
USER node
EXPOSE 3000

CMD ["node", "server.js"]
