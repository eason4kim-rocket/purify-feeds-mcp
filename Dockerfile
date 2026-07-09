FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /purify-feeds-mcp .

FROM gcr.io/distroless/static-debian12:nonroot
LABEL io.modelcontextprotocol.server.name="io.github.eason4kim-rocket/purify-feeds-mcp"
LABEL org.opencontainers.image.source="https://github.com/eason4kim-rocket/purify-feeds-mcp"
LABEL org.opencontainers.image.description="MCP server for Purify's auditable security-intelligence feeds (CISA KEV / EPSS / enriched)"
LABEL org.opencontainers.image.licenses="MIT"
ENV PURIFY_API_URL="https://feeds.verifly.pro/feeds-api"
COPY --from=build /purify-feeds-mcp /purify-feeds-mcp
ENTRYPOINT ["/purify-feeds-mcp"]
