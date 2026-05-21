"""Centralised logging configuration for the entire pipeline."""
import logging
import sys
from pathlib import Path


def get_logger(name: str, log_file: str = None, level: int = logging.INFO) -> logging.Logger:
    """
    Return a logger with a consistent format.

    Args:
        name: Logger name (typically __name__).
        log_file: Optional path to write logs to disk.
        level: Logging level.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Optional file handler
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger
