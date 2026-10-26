# ajant frontend — Faz 01 iskelet imajı (Faz 05'te olgunlaştırılacak)
FROM node:22-alpine

WORKDIR /app

ENV NEXT_TELEMETRY_DISABLED=1

COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY . .
RUN npm run build

USER node
EXPOSE 3000

CMD ["npm", "run", "start"]
