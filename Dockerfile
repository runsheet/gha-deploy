FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /gha-deploy .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /gha-deploy /gha-deploy
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/gha-deploy"]
