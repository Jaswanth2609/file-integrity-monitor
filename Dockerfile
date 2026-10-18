# File Integrity Monitor (FIM) v2.3 Container
FROM python:3.12-slim AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Final Runtime Image
FROM python:3.12-slim

LABEL maintainer="Jaswanth <jaswanth@users.noreply.github.com>"
LABEL version="2.3.0"
LABEL description="File Integrity Monitor (FIM) with Ed25519 signing and Threat Intelligence"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/install/bin:$PATH" \
    PYTHONPATH="/install/lib/python3.12/site-packages:$PYTHONPATH" \
    HOME="/home/fim"

# Create unprivileged system group and user
RUN groupadd -r fim && useradd -r -g fim -m -d /home/fim -s /sbin/nologin fim

WORKDIR /app

COPY --from=builder /install /install
COPY . /app

# Ensure proper non-root permissions
RUN chown -R fim:fim /app /home/fim

USER fim

# Expose Web Dashboard and REST API port
EXPOSE 8000

# Default healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health').read()" || exit 1

ENTRYPOINT ["python3", "main.py"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000", "--allow-remote"]
