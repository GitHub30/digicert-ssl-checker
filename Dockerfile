FROM ghcr.io/puppeteer/puppeteer:latest

COPY package*.json ./

RUN npm ci --omit=dev

COPY . .

ENTRYPOINT ["node", "index.mjs"]