# ==============================================================================
# OctoLAN - Dockerfile (Multi-Stage Production Build)
# ==============================================================================

FROM docker.io/library/node:22-alpine AS builder

WORKDIR /app

COPY package.json ./
RUN npm install

COPY tsconfig.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src

RUN npm run build

FROM docker.io/nginxinc/nginx-unprivileged:alpine AS runtime

LABEL maintainer="OctoLAN Network Engineering Suite" \
      description="OctoLAN On-Premise Network Intelligence & Telemetry Console" \
      version="1.0.0"

COPY --chown=101:101 nginx.conf /etc/nginx/nginx.conf
COPY --from=builder --chown=101:101 /app/dist /usr/share/nginx/html

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:3000/health || exit 1

USER 101
CMD ["nginx", "-g", "daemon off;"]
