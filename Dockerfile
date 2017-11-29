FROM node:carbon-alpine

# Install OpenSSL binaries
RUN apk add --no-cache openssl

# Configure the environment
ENV NODE_ENV=production
ENV LOG4JS_CONFIG=/app/log4js.json

WORKDIR /app
ENTRYPOINT ["npm", "start", "--"]

# Install the application
RUN mkdir -p /app
ADD deploy/ /app
