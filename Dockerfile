# Pinned by digest so a rebuild can't silently pull a different base image.
# This MUST be the multi-arch manifest-LIST digest (resolves per-platform), not
# a single-arch image digest — the latter builds an arm64 binary that fails on
# amd64 CI with "exec format error". Refresh with the registry's manifest-list
# digest, e.g. `docker buildx imagetools inspect node:26-alpine`; Dependabot's
# docker ecosystem pins the list digest correctly too.
FROM node:26-alpine@sha256:9c0e1e52125d6b67d505cf75b4880fcf1290ccea5c480849910e1d57b2cf72b5 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsup.config.ts ./
COPY scripts ./scripts
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:26-alpine@sha256:9c0e1e52125d6b67d505cf75b4880fcf1290ccea5c480849910e1d57b2cf72b5
WORKDIR /app
ENV NODE_ENV=production HOST=0.0.0.0 PORT=12345
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
USER node
EXPOSE 12345
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:12345/healthz || exit 1
CMD ["node", "dist/index.js"]
