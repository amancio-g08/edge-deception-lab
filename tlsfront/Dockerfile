FROM golang:1.24-alpine AS build
WORKDIR /src
# no external modules, so there is nothing to download and the build works offline
COPY tlsfront/ ./tlsfront/
WORKDIR /src/tlsfront
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tlsfront .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tlsfront /tlsfront
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/tlsfront"]
