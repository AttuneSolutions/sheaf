"""`sheaf-approve`: run the approval page (standard 7.6), configured from the environment
(`sheaf_approve.settings`), on SHEAF_APPROVE_HOST (default 0.0.0.0) and SHEAF_APPROVE_PORT
(default 8080). Publish it only through the tenant's reverse proxy, over HTTPS."""

import logging
import os
import sys

import httpx
import uvicorn
from fastapi import FastAPI

from sheaf_approve.app import TIMEOUT, create_app
from sheaf_approve.settings import Settings, listen_from


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # httpx logs each request's address at INFO; keep the log to the service's own lines.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def create() -> FastAPI:
    settings = Settings.from_env(os.environ)
    # No proxy from the environment: each request carries a person's token.
    http = httpx.Client(timeout=TIMEOUT, trust_env=False)
    return create_app(settings, http)


def main() -> int:
    configure_logging()
    try:
        Settings.from_env(os.environ)
        host, port = listen_from(os.environ)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 2
    uvicorn.run(
        "sheaf_approve.__main__:create",
        factory=True,
        host=host,
        port=port,
        access_log=False,
        log_config=None,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
