FROM node:22-slim
WORKDIR /app
COPY . .
RUN npm ci && npm run build
WORKDIR /app/test-mcp-server
RUN npm ci
EXPOSE 3000
CMD ["node_modules/.bin/tsx", "bin/mcp_server.mts", "cucumber"]
