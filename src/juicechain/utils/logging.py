from __future__ import annotations

import logging
from pathlib import Path


DEFAULT_LOG_FILE = Path(".juicechain") / "juicechain.log"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def resolve_log_level(level: str) -> int:
    name = (level or "INFO").upper().strip()
    mapping = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    return mapping.get(name, logging.INFO)


def configure_logging(
    *,
    level: str = "INFO",
    log_file: str | Path | None = None,
    enable_file: bool = True,
) -> Path | None:
    logger = logging.getLogger("juicechain")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    console = logging.StreamHandler()
    console.setLevel(resolve_log_level(level))
    console.setFormatter(formatter)
    logger.addHandler(console)

    file_path: Path | None = None
    if enable_file:
        file_path = Path(log_file) if log_file else DEFAULT_LOG_FILE
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return file_path


def get_logger(name: str) -> logging.Logger:
    if name.startswith("juicechain"):
        return logging.getLogger(name)
    return logging.getLogger(f"juicechain.{name}")
