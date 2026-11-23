# One image for every Sheaf workload (standard 7.1): the gateway by default, the witness job
# as a scheduled Container Apps job running `python -m sheaf_witness` with its own identity, and
# the approval page (`sheaf-approve`, standard 7.6) as its own app with no Azure credential.
# `sheaf-admin` is in it too, so a mandate can be checked with the released code.
# A mandate records its digest as `gateway.image`, so anyone must be able to rebuild the same
# digest from the same commit: base images are pinned by digest, and file times come from the
# commit, not the build.
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
#     --output type=image,name=sheaf:dev,rewrite-timestamp=true .

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.3@sha256:90bbb3c16635e9627f49eec6539f956d70746c409209041800a0280b93152823

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
# Set, this makes Python write hash-checked .pyc files, which carry no timestamps.
ARG SOURCE_DATE_EPOCH
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app
WORKDIR /src

# Locked third-party dependencies first, so a code change does not fetch them again.
COPY pyproject.toml uv.lock ./
COPY packages/admin/pyproject.toml packages/admin/
COPY packages/approve/pyproject.toml packages/approve/
COPY packages/core/pyproject.toml packages/core/
COPY packages/gateway/pyproject.toml packages/gateway/
COPY packages/witness/pyproject.toml packages/witness/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-workspace --all-packages

COPY packages packages
# uv notes when it built each workspace package (uv_cache.json); that is its own reinstall
# cache, not part of the package, and the only thing that differed between two builds.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable --all-packages \
    && find /app -path '*.dist-info/uv_cache.json' -delete \
    && sed -i '/\/uv_cache\.json,/d' /app/lib/python3.*/site-packages/*.dist-info/RECORD

FROM ${PYTHON_IMAGE}
# Fixed labels only: a build time here would change the digest a mandate records.
LABEL org.opencontainers.image.title="Sheaf" \
      org.opencontainers.image.description="Sheaf write gateway, witness job and approval page" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/AttuneSolutions/sheaf"
COPY --from=build /app /app
ENV PATH=/app/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# A fixed numeric user, not one created with useradd, which stamps the build date into
# /etc/shadow. /app stays owned by root and read-only to the process.
USER 65532:65532
EXPOSE 8080
CMD ["uvicorn", "--factory", "sheaf_gateway.main:create", "--host", "0.0.0.0", "--port", "8080"]
