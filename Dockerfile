# syntax=docker/dockerfile:1.7

# ---------- builder ----------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpq-dev libffi-dev \
        libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app ./app
COPY alembic.ini ./
COPY alembic ./alembic

RUN pip install --upgrade pip build \
    && pip wheel --wheel-dir /wheels '.[postgres]'

# ---------- runtime (distroless-style minimal) ----------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SUNDOWN_ENV=production

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 libffi8 \
        libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
        curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r sundown && useradd -r -g sundown -d /app -s /sbin/nologin sundown \
    && mkdir -p /app/data /app/reports/output \
    && chown -R sundown:sundown /app

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels sundown[postgres] \
    && rm -rf /wheels

COPY --chown=sundown:sundown app ./app
COPY --chown=sundown:sundown alembic.ini ./alembic.ini
COPY --chown=sundown:sundown alembic ./alembic
COPY --chown=sundown:sundown scripts ./scripts

USER sundown

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers"]
