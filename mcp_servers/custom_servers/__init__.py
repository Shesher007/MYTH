from myth_config import load_dotenv

load_dotenv()

# Custom MCP servers
from .security_tools import mcp as security_tools_server  # noqa: E402

# from .project_discovery import mcp as project_discovery_server

__all__ = ["security_tools_server"]
