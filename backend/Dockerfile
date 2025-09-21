FROM node:18

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN mkdir -p uploads
EXPOSE 5000
# Run migrations first, then start the server
CMD ["sh", "-c", "node migrations/init.js && node server.js"]
