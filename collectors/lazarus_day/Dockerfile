FROM python:3.10-slim-bookworm

ARG PIP_INDEX_URL=https://pypi.org/simple

WORKDIR /collector

COPY requirements-api.txt ./requirements-api.txt
RUN pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" -r requirements-api.txt

COPY scripts/ ./scripts/
COPY docs/ ./docs/
COPY data/reference/ ./data/reference/

RUN useradd --uid 10001 --user-group --home-dir /collector \
      --shell /usr/sbin/nologin collector \
    && mkdir -p /collector/data/events/state/api /collector/logs/api \
    && chown -R collector:collector /collector

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/collector \
    LAZARUS_DAY_PROJECT_ROOT=/collector

USER collector

EXPOSE 8788

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c 'import os, urllib.request; r=urllib.request.Request("http://127.0.0.1:8788/readyz", headers={"X-API-Key": os.environ.get("LAZARUS_DAY_API_KEY", "")}); urllib.request.urlopen(r, timeout=5).read()' || exit 1

CMD ["python", "-m", "uvicorn", "scripts.lazarus_day.api:app", "--host", "0.0.0.0", "--port", "8788", "--workers", "1", "--no-access-log"]
