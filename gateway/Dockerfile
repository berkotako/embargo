# Build the plugin, then package it into the Verdaccio image as a storage
# filter named `verdaccio-embargo` (the name Verdaccio resolves `embargo` to).
#
# NOTE: the build context must be the repo root so the engine proto can be
# bundled:  docker build -f gateway/Dockerfile -t embargo-gateway .

FROM node:20-alpine AS builder
WORKDIR /plugin
COPY gateway/package.json gateway/package-lock.json* ./
RUN npm ci
COPY gateway/tsconfig.json ./
COPY gateway/src/ src/
RUN npm run build && npm prune --omit=dev

FROM verdaccio/verdaccio:6
USER root
ENV EMBARGO_PROTO_DIR=/verdaccio/plugins/verdaccio-embargo/proto
# Install the plugin module as verdaccio-embargo (dist + runtime deps + proto).
COPY --from=builder /plugin/dist            /verdaccio/plugins/verdaccio-embargo/dist
COPY --from=builder /plugin/node_modules    /verdaccio/plugins/verdaccio-embargo/node_modules
COPY --from=builder /plugin/package.json    /verdaccio/plugins/verdaccio-embargo/package.json
COPY engine/proto/                          /verdaccio/plugins/verdaccio-embargo/proto/
COPY gateway/verdaccio.config.yaml          /verdaccio/conf/config.yaml
RUN chown -R 10001:65533 /verdaccio/plugins /verdaccio/conf
USER 10001
EXPOSE 4873
