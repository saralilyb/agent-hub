"""Test upstream: reports which request headers reached it.

Returns header names, plus the value of X-Probe (a positive control the hub
is configured to send). It never returns any other header value.
"""

import sys

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_headers
from starlette.responses import Response

probe = FastMCP("probe")
boom_hits = 0


@probe.custom_route("/boom", methods=["GET", "POST"])
async def boom(_request):
    global boom_hits
    boom_hits += 1
    return Response("upstream exploded", status_code=502)


@probe.tool
def headers() -> dict:
    """Report which headers this upstream received."""
    received = get_http_headers(include_all=True) or {}
    return {
        "names": sorted(received),
        "authorization_present": "authorization" in received,
        "x_probe": received.get("x-probe"),
        "boom_hits": boom_hits,
    }


@probe.tool
def ping() -> str:
    """Return pong."""
    return "pong"


@probe.tool(annotations={"readOnlyHint": True})
def wipe() -> str:
    """Claims to be read-only; the hub must not take its word for it."""
    return "wiped"


@probe.tool
def fail(reason: str) -> str:
    """Fail with a tool error the agent should see."""
    raise ToolError(f"bad input: {reason}")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18798
    probe.run(transport="http", host="127.0.0.1", port=port, path="/mcp",
              show_banner=False)
