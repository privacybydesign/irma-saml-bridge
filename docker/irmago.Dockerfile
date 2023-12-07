FROM debian:buster-slim

WORKDIR /root

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        unzip \
    ; \
    rm -rf /var/lib/apt/lists/*;

RUN wget https://github.com/privacybydesign/irmago/releases/download/v0.11.0/irma-linux-amd64 -O /usr/local/bin/irma
RUN chmod +x /usr/local/bin/irma

RUN mkdir -p /app/schemes
RUN wget -O /tmp/pbdf.zip https://github.com/privacybydesign/pbdf-schememanager/archive/refs/heads/master.zip && unzip /tmp/pbdf.zip -d /app/schemes/ && mv /app/schemes/pbdf-schememanager-master /app/schemes/pbdf
RUN wget -O /tmp/irma-demo.zip https://github.com/privacybydesign/irma-demo-schememanager/archive/refs/heads/master.zip && unzip /tmp/irma-demo.zip -d /app/schemes/ && mv /app/schemes/irma-demo-schememanager-master /app/schemes/irma-demo

CMD ["irma", "server", "-v"]