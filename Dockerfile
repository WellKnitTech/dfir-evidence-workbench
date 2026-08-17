# Pinned Python 3.11 slim image for reproducible API builds.
# Hardened for least-privilege:
# - non-root runtime user
# - no unnecessary packages
# - no secrets, credentials, or evidence in image layers
# - runtime security (read_only fs, dropped caps, no-new-privs, resource limits, tmpfs)
#   is enforced in compose.yaml / compose.*.yaml (not Dockerfile)
# - source copied for prod build; dev overrides with volume mount
FROM docker.io/library/python@sha256:78b39ef14d8e2b4d71f8dc304f1328c37df95fe0ef99477c2ae6bd3d03784553

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Create non-root user early (uid/gid chosen to avoid host conflicts in rootless Podman)
RUN useradd -m -u 10001 -U appuser

# Copy package metadata + source BEFORE install so editable layout and package discovery succeed in build
COPY pyproject.toml ./
COPY requirements-api.lock ./
COPY --chown=appuser:appuser src ./src
COPY --chown=appuser:appuser migrations ./migrations

# Install the api extra (FastAPI + uvicorn + pydantic-settings + psycopg)
# Use non-editable install for the baked image (dev compose will volume-mount source on top for reload)
RUN python -m pip install --disable-pip-version-check --no-cache-dir -r requirements-api.lock && \
    python -m pip install --disable-pip-version-check --no-cache-dir --no-build-isolation --no-deps . && \
    rm -rf /root/.cache/pip /root/.cache

# Ensure app dir owned (safe even if some files root); appuser has no write in prod runs
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

# Default command (uvicorn reads DFIRWB_* env; host 0.0.0.0 inside container)
CMD ["uvicorn", "dfir_workbench.api:app", "--host", "0.0.0.0", "--port", "8080"]
