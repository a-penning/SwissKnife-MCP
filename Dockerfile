# Pinned by digest so a rebuild can't silently pull a different base image.
# Refresh with: docker buildx imagetools inspect node:22-alpine (Dependabot's
# docker ecosystem keeps this current too).
FROM node:22-alpine@sha256:9385cd9f3001dfc3431e8ead12c43e9e1f87cc1b9b5c6cfd0f73865d405b27c4 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsup.config.ts ./
COPY scripts ./scripts
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine@sha256:9385cd9f3001dfc3431e8ead12c43e9e1f87cc1b9b5c6cfd0f73865d405b27c4
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
