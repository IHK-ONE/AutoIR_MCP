import logging
import sys

from core.server import mcp


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING, force=True)
    logging.getLogger("mcp").setLevel(logging.WARNING)
    logging.getLogger("fastmcp").setLevel(logging.WARNING)
    mcp.run()
