# Pinned by digest so a rebuild can't silently pull a different base image.
# Refresh with: docker buildx imagetools inspect node:22-alpine (Dependabot's
# docker ecosystem keeps this current too).
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
