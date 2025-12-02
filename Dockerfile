FROM python:3.12-slim-bookworm AS bwcli
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget unzip && \
    wget -O "bw.zip" "https://vault.bitwarden.com/download/?app=cli&platform=linux" && \
    unzip bw.zip && \
    chmod +x ./bw

FROM python:3.12-slim-bookworm AS builder
WORKDIR /app

COPY pyproject.toml poetry.lock ./
RUN pip install --no-cache-dir poetry && \
    poetry self add poetry-plugin-export && \
    poetry export --without-hashes -f requirements.txt -o requirements.txt

FROM python:3.12-slim-bookworm

COPY --from=bwcli /bw /usr/local/bin/bw

WORKDIR /bitwarden-to-keepass
COPY --from=builder /app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DATABASE_PATH=/exports/bitwarden-export.kdbx
ENV BW_PATH=/usr/local/bin/bw

ENTRYPOINT ["/bin/bash", "/bitwarden-to-keepass/entrypoint.sh"]
