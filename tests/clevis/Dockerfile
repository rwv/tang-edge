FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates clevis clevis-luks cryptsetup-bin curl jq \
    && rm -rf /var/lib/apt/lists/*
COPY e2e.sh /usr/local/bin/tang-clevis-e2e
RUN chmod 755 /usr/local/bin/tang-clevis-e2e
ENTRYPOINT ["/usr/local/bin/tang-clevis-e2e"]
