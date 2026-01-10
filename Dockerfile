# Stage 1: Build the NestJS app
FROM node:18-alpine AS builder

WORKDIR /app

# Copy dependency files
COPY package*.json ./

# Install all dependencies (including devDependencies for build)
RUN npm install

# Copy source code
COPY . .

# Generate the production build (creates the dist folder)
RUN npm run build

# Stage 2: Run the production server
FROM node:18-alpine

WORKDIR /app

# Copy only the necessary files for production
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/dist ./dist

# Install production dependencies only to keep the image small
RUN npm install --only=production

# NestJS default port
EXPOSE 3000

# Start the application
CMD ["node", "dist/main"]