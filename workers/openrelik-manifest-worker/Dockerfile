# amd64 manifest digest for python:3.11-slim (3.11.16-slim-trixie).
FROM docker.io/library/python@sha256:ff05d1a05204fb9f7444c435db8e8ec104e587a413280dc9ffc27a4797554182

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /worker
COPY pyproject.toml ./
COPY src ./src
RUN python -m pip install --no-cache-dir --no-deps .
USER 65532:65532
ENTRYPOINT ["openrelik-manifest-worker"]
