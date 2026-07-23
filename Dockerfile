# OneGate gateway image.
#
#   docker build -t onegate .
#   docker run -d --name onegate -p 8443:8443 -p 8080:8080 -v onegate-data:/data onegate
#
# First run initializes the data dir and prints the one-time admin token to
# the container log: docker logs onegate

FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json ./
COPY src ./src
RUN pnpm build && pnpm prune --prod

FROM node:22-alpine
ENV NODE_ENV=production \
    ONEGATE_DATA=/data \
    ONEGATE_PROXY_PORT=8443 \
    ONEGATE_ADMIN_PORT=8080
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY bin ./bin
COPY package.json docker/entrypoint.sh ./
RUN chmod +x entrypoint.sh && mkdir /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 8443 8080
ENTRYPOINT ["./entrypoint.sh"]
