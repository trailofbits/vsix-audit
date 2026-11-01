ARG NODE=node:24.22.2-bookworm-slim
ARG TARGETARCH
ARG YARA_RELEASE=https://github.com/VirusTotal/yara-x/releases/download/v1.22.1

FROM ${NODE}@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c AS base

FROM scratch AS yara-amd64
ARG YARA_RELEASE
ADD --checksum=sha256:c0ff80408d57b94f8348b9b19b5c70fb03e6471e7fdd761c97e0b4876804eecf \
    ${YARA_RELEASE}/yara-x-v1.22.1-x86_64-unknown-linux-gnu.tar.gz \
    /yara-x.tar.gz

FROM scratch AS yara-arm64
ARG YARA_RELEASE
ADD --checksum=sha256:bdddb06ca550319c26aab57d2ee0ea792b0a5175565b22f1ba04813937450fb7 \
    ${YARA_RELEASE}/yara-x-v1.22.1-aarch64-unknown-linux-gnu.tar.gz \
    /yara-x.tar.gz

# Select the checksum-verified build stage for the target architecture.
# hadolint ignore=DL3006
FROM yara-${TARGETARCH} AS yara

FROM base AS build
WORKDIR /opt/vsix-audit
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsconfig.build.json ./
COPY scripts/clean-build.mjs ./scripts/clean-build.mjs
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts
COPY --from=yara /yara-x.tar.gz /tmp/yara-x.tar.gz
RUN tar -xzf /tmp/yara-x.tar.gz -C /usr/local/bin yr

FROM base AS runtime
ENV NODE_ENV=production
LABEL org.opencontainers.image.source="https://github.com/trailofbits/vsix-audit" \
    org.opencontainers.image.description="Security scanner for VS Code extensions" \
    org.opencontainers.image.licenses="AGPL-3.0"
COPY --from=build /opt/vsix-audit/package.json /opt/vsix-audit/package.json
COPY --from=build /opt/vsix-audit/node_modules /opt/vsix-audit/node_modules
COPY --from=build /opt/vsix-audit/dist /opt/vsix-audit/dist
COPY --from=build /usr/local/bin/yr /usr/local/bin/yr
COPY zoo/blocklist /opt/vsix-audit/zoo/blocklist
COPY zoo/iocs /opt/vsix-audit/zoo/iocs
COPY zoo/signatures /opt/vsix-audit/zoo/signatures
COPY zoo/telemetry /opt/vsix-audit/zoo/telemetry
COPY LICENSE /opt/vsix-audit/LICENSE
COPY licenses/YARA-X /usr/local/share/doc/yara-x/LICENSE
WORKDIR /work
RUN chown node:node /work
USER node
ENTRYPOINT ["node", "/opt/vsix-audit/dist/index.js"]
CMD ["--help"]
