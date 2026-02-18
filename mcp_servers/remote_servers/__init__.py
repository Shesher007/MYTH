from myth_config import load_dotenv
load_dotenv()

# Remote MCP servers
from .external_apis import mcp as external_apis_server

__all__ = ['external_apis_server']
