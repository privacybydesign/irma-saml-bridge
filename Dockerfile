####################
# Frontend assets
####################
FROM node:24-slim AS assets
WORKDIR /app/assets

COPY assets/package.json assets/yarn.lock ./
# No install scripts: the bundler's native parts come as prebuilt packages.
RUN yarn install --frozen-lockfile --ignore-scripts

COPY assets/ ./
RUN yarn run build

####################
# Go build
####################
FROM golang:1.26.11 AS build
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=assets /app/assets/dist/ ./static/assets/

# The script and the style sheet of the page are built by the stage above
# and embedded into the binary: fail the build if they are missing.
RUN test -s static/assets/app.js && test -s static/assets/app.css

RUN CGO_ENABLED=0 go build -trimpath -o /irma-saml-bridge .

####################
# Runtime image
####################
FROM alpine:3.24 AS runtime

# The deployment (irma-saml-bridge-ops) starts the container with
# "/bin/sh -c scripts/entrypoint.sh". That script creates /usr/local/keys and
# converts the mounted PEM keys to DER with openssl before it starts the
# bridge, so the image needs a shell, openssl and a writable /usr/local.
#
# The packages of the base image are upgraded first: a base image can be
# weeks behind on fixes, and the image scan fails on a fixable critical one.
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates openssl \
    && adduser -D -H -u 65532 nonroot \
    && chown nonroot:nonroot /usr/local

COPY --from=build /irma-saml-bridge /irma-saml-bridge

USER nonroot:nonroot

EXPOSE 8080
ENTRYPOINT ["/irma-saml-bridge"]
