import logging
import sys
from app.config import config

# Create logger
logger = logging.getLogger("SISA_Platform")
logger.setLevel(config.LOG_LEVEL)

# Console handler
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(config.LOG_LEVEL)

# Formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
handler.setFormatter(formatter)

# Add handler to logger
if not logger.handlers:
    logger.addHandler(handler)
