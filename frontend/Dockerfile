FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 5173
# Expose host for vite
CMD ["npm", "run", "dev", "--", "--host"]
