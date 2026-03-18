# syntax=docker/dockerfile:1.7
# Seraph AI Defense System - Frontend Dockerfile
# ===============================================
# Multi-stage build for React app with Seraphic Watch theme

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies
RUN --mount=type=cache,target=/usr/local/share/.cache/yarn \
    corepack enable && yarn install --no-lockfile

# Copy source code
COPY . .

# Build argument for backend URL
ARG REACT_APP_BACKEND_URL=
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL

# Increase Node.js memory for build
ENV NODE_OPTIONS="--max-old-space-size=4096"
ENV GENERATE_SOURCEMAP=false

# Build the application
RUN yarn build

# Stage 2: Production
FROM nginx:alpine

LABEL maintainer="Seraph AI Team"
LABEL description="Seraph AI Defense System Frontend"
LABEL version="5.0.0"

# Copy built files
COPY --from=builder /app/build /usr/share/nginx/html

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy health/wait helper
COPY wait-for-backend.sh /wait-for-backend.sh
RUN chmod +x /wait-for-backend.sh

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://127.0.0.1/ || exit 1

# Run wait wrapper which starts nginx after backend DNS resolves
CMD ["/wait-for-backend.sh"]
