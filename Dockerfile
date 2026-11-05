# Exposure Guard - Debian packages only (no pip wheels), works on arm64 and amd64.
FROM debian:trixie-slim AS base
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-yaml python3-nacl python3-cryptography \
      nmap iproute2 openssh-client ieee-data ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --home-dir /data --shell /usr/sbin/nologin guard
WORKDIR /opt/exposure-guard
COPY exposure_guard ./exposure_guard
COPY probe ./probe
RUN printf '#!/bin/sh\nexec python3 -m exposure_guard "$@"\n' > /usr/local/bin/exposure-guard \
 && chmod 755 /usr/local/bin/exposure-guard
ENV PYTHONPATH=/opt/exposure-guard EXPOSURE_GUARD_CONFIG=/config/config.yaml HOME=/data

FROM base AS test
RUN apt-get update && apt-get install -y --no-install-recommends python3-pytest && rm -rf /var/lib/apt/lists/*
COPY tests ./tests
COPY pyproject.toml ./
USER 10001
CMD ["python3", "-m", "pytest", "-q", "tests/unit"]

FROM base AS app
USER 10001
EXPOSE 8103
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8103/api/health', timeout=4).status == 200 else 1)"
CMD ["exposure-guard", "serve"]
