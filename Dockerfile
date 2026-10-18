FROM golang:1.27-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY pkg ./pkg
COPY main.go vuln_db.json ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/fenrir .

FROM python:3.13-slim
COPY --from=build /out/fenrir /usr/src/app/fenrir
COPY vuln_db.json /usr/src/app/vuln_db.json
COPY main.py /usr/src/app/
WORKDIR /usr/src/app

CMD ["python3", "main.py"]
