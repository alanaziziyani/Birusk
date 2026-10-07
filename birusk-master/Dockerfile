# ---------- مرحله ۱: دانلود xray-core ----------
FROM alpine:latest AS xraydl
RUN apk add --no-cache curl unzip
WORKDIR /xray
RUN curl -fsSL -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
    && unzip xray.zip xray geoip.dat geosite.dat \
    && chmod +x xray

# ---------- مرحله ۲: بیلد برنامه‌ی Go ----------
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

COPY go.mod ./
COPY . .

RUN go mod tidy
RUN go mod download

RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o birusk-master .

# ---------- مرحله ۳: ایمیج نهایی ----------
FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/birusk-master .
COPY --from=builder /app/ui ./ui
COPY --from=xraydl /xray/xray ./xray
COPY --from=xraydl /xray/geoip.dat ./geoip.dat
COPY --from=xraydl /xray/geosite.dat ./geosite.dat

ENV XRAY_LOCATION_ASSET=/app
EXPOSE 8080
ENV PORT=8080

CMD ["./birusk-master"]
