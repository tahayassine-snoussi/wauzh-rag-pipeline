"""
Shared logging configuration for the Sigma -> Wazuh pipeline.
"""

import logging
import sys
import os
from datetime import datetime


def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Create a logger with colored console output and file output.

    Args:
        name: Logger name (e.g., "ingestion", "retrieval", "validator")
        level: Logging level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
        "RESET": "\033[0m",
    }

    class ColoredFormatter(logging.Formatter):
        def format(self, record):
            color = COLORS.get(record.levelname, COLORS["RESET"])
            reset = COLORS["RESET"]
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            msg = f"{color}[{timestamp}] [{record.levelname:8}] [{record.name:12}]{reset} {record.getMessage()}"
            return msg

    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)

    # File handler
    file_handler = logging.FileHandler(f"logs/{name}.log", mode="a")
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-12s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger