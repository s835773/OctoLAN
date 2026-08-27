# ==============================================================================
# OctoLAN - Containerfile for Podman & Docker (Rootless Multi-Stage Build)
# ==============================================================================

# --- Stage 1: Build Frontend Assets ---
FROM docker.io/library/node:22-alpine AS builder

WORKDIR /app

# Cache package manifests first
COPY package.json ./

# Install dependencies (reproducible build)
RUN npm install

# Copy source code and config files
COPY tsconfig.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src

# Build production SPA
RUN npm run build

# --- Stage 2: Minimal Production Runtime ---
FROM docker.io/nginxinc/nginx-unprivileged:alpine AS runtime

LABEL maintainer="OctoLAN Network Engineering Suite" \
      description="OctoLAN On-Premise Network Intelligence & Telemetry Console" \
      version="1.0.0"

# Copy custom rootless Nginx configuration
COPY --chown=101:101 nginx.conf /etc/nginx/nginx.conf

# Copy compiled static assets from builder stage
COPY --from=builder --chown=101:101 /app/dist /usr/share/nginx/html

# Expose unprivileged web port
EXPOSE 3000

# Healthcheck for container managers (Podman, Docker, Kubernetes)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:3000/health || exit 1

# Run unprivileged nginx
USER 101
CMD ["nginx", "-g", "daemon off;"]
