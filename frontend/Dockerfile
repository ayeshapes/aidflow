FROM node:20

WORKDIR /app

# Copy package files first so the npm install layer is cached.
COPY package*.json ./
RUN npm install

COPY . .

# Vite dev server on 5173 (host/port are set in vite.config.js).
CMD ["npm", "run", "dev"]
