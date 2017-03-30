FROM node:boron-alpine

# Install OpenSSL binaries
RUN apk add --no-cache openssl

# Configure the environment
ENV NODE_ENV=production

WORKDIR /app
ENTRYPOINT ["npm", "start", "--"]

# Install the application
RUN mkdir -p /app
ADD deploy/ /app
