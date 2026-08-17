FROM node:22-alpine AS build
ARG VITE_SCADAGUARD_WEB_VERSION=0.1.0
ARG VITE_SCADAGUARD_BUILD=development
ENV VITE_SCADAGUARD_WEB_VERSION=${VITE_SCADAGUARD_WEB_VERSION} \
    VITE_SCADAGUARD_BUILD=${VITE_SCADAGUARD_BUILD}
RUN corepack enable
WORKDIR /build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM caddy:2.10-alpine
COPY --from=build /build/dist /srv
COPY Caddyfile /etc/caddy/Caddyfile
EXPOSE 8080
