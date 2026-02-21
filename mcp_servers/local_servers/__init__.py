from myth_config import load_dotenv

load_dotenv()

# Local MCP servers
from .system_tools import mcp as system_tools_server  # noqa: E402

__all__ = ["system_tools_server"]
