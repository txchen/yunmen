# syntax=docker/dockerfile:1
FROM node:24-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/txchen/yunmen/internal/version.Version=${VERSION}" -o /out/yunmen-server ./cmd/yunmen-server && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go /out/yunmen-server /usr/local/bin/yunmen-server
COPY --from=go --chown=nonroot:nonroot /out/data /data
ENV YUNMEN_DATA_DIR=/data YUNMEN_LISTEN=0.0.0.0:8080
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/yunmen-server"]
CMD ["serve"]
