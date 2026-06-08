FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json vite.config.ts index.html ./
COPY src/ src/
# Auth mode is inlined at build time (Vite). Match the engine's auth.mode.
ARG VITE_AUTH_MODE=disabled
ENV VITE_AUTH_MODE=$VITE_AUTH_MODE
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 4000
