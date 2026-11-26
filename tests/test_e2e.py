"""End-to-end: a real hub process, a probe upstream, real MCP clients.

Tokens are generated per run; nothing here needs a secrets store or the
network beyond 127.0.0.1.
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx2 as httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import (
    StdioTransport,
    StreamableHttpTransport,
)

ROOT = Path(__file__).resolve().parent.parent
LEAK = "SUPERSECRET_LEAK_TEST_TOKEN_999"
STATUS_PW = "status-" + secrets.token_hex(8)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port, proc, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited with {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"port {port} never opened")


def _sha(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _config(probe_port, hub_port, state, tokens, extra_agents=""):
    t = tokens
    return f"""
[hub]
name = "e2e-hub"
port = {hub_port}
state_dir = "{state}"

[hub.status]
user = "ops"
password = "env:E2E_STATUS_PW"

[upstreams.probe]
url = "http://127.0.0.1:{probe_port}/mcp"
headers = {{ X-Probe = "ok" }}

[upstreams.broken]
url = "http://127.0.0.1:{probe_port}/boom?token={LEAK}"

[groups.probe-read]
access = "read"
allow = ["probe_headers", "probe_ping"]

[groups.probe-write]
allow = ["probe_wipe", "probe_fail"]

[agents.full]
token_sha256 = ["{_sha(t['full'])}", "{_sha(t['full-new'])}"]
groups = ["probe-read", "probe-write"]
allow = ["broken_fail"]

[agents.narrow]
token_sha256 = "{_sha(t['narrow'])}"
groups = ["probe-read"]
read_only = true

[agents.expired]
token_sha256 = "{_sha(t['expired'])}"
groups = ["probe-read"]
expires = 2020-01-01
{extra_agents}"""


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")
    tokens = {
        n: secrets.token_hex(32)
        for n in ("full", "full-new", "narrow", "expired", "late")
    }
    probe_port, hub_port = _free_port(), _free_port()
    config = tmp / "hub.toml"
    config.write_text(_config(probe_port, hub_port, tmp / "state", tokens))
    env = {
        **os.environ,
        "E2E_STATUS_PW": STATUS_PW,
        "FASTMCP_CHECK_FOR_UPDATES": "off",
    }
    env.pop("AGENT_HUB_CONFIG", None)
    probe = subprocess.Popen(
        [sys.executable, str(ROOT / "tests" / "probe.py"), str(probe_port)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    log = (tmp / "hub.log").open("w")
    hub = subprocess.Popen(
        [sys.executable, str(ROOT / "hub.py"), "serve", "--config",
         str(config)],
        env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        _wait_port(probe_port, probe)
        _wait_port(hub_port, hub)
        yield {
            "url": f"http://127.0.0.1:{hub_port}/mcp",
            "base": f"http://127.0.0.1:{hub_port}",
            "tokens": tokens,
            "config": config,
            "tmp": tmp,
            "probe_port": probe_port,
            "hub_port": hub_port,
            "log": tmp / "hub.log",
            "env": env,
        }
    finally:
        for proc in (hub, probe):
            proc.send_signal(signal.SIGTERM)
        for proc in (hub, probe):
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        log.close()


def _client(stack, token):
    headers = {"Authorization": f"Bearer {token}"}
    return Client(StreamableHttpTransport(stack["url"], headers=headers))


def _text(result):
    return "".join(getattr(c, "text", "") for c in result.content)


def _run(coro):
    return asyncio.run(coro)


def test_narrow_agent_sees_and_calls_only_its_tools(stack):
    async def go():
        async with _client(stack, stack["tokens"]["narrow"]) as c:
            names = sorted(t.name for t in await c.list_tools())
            probe = json.loads(_text(await c.call_tool("probe_headers", {})))
            denied = await c.call_tool("probe_wipe", {}, raise_on_error=False)
            unknown = await c.call_tool(
                "probe_nonexistent", {}, raise_on_error=False)
            return names, probe, denied, unknown

    names, probe, denied, unknown = _run(go())
    assert names == ["probe_headers", "probe_ping"]
    # An upstream no allowed tool lives on is never contacted.
    assert probe["boom_hits"] == 0
    assert denied.is_error and _text(denied) == "tool not available"
    assert _text(unknown) == _text(denied)


def test_headers_and_credentials_upstream(stack):
    async def go():
        async with _client(stack, stack["tokens"]["full"]) as c:
            return json.loads(_text(await c.call_tool("probe_headers", {})))

    probe = _run(go())
    assert probe["x_probe"] == "ok"
    assert probe["authorization_present"] is False


def test_failing_upstream_is_isolated_and_masked(stack):
    async def go():
        async with _client(stack, stack["tokens"]["full"]) as c:
            names = {t.name for t in await c.list_tools()}
            broken = await c.call_tool(
                "broken_fail", {}, raise_on_error=False)
            failed = await c.call_tool(
                "probe_fail", {"reason": "no such date"},
                raise_on_error=False)
            return names, broken, failed

    names, broken, failed = _run(go())
    assert "probe_ping" in names
    assert broken.is_error
    assert LEAK not in _text(broken) and "token=" not in _text(broken)
    # The upstream's own tool error still reaches the agent.
    assert failed.is_error and "bad input: no such date" in _text(failed)


def test_hub_owns_read_only_hints(stack):
    async def go():
        async with _client(stack, stack["tokens"]["full"]) as c:
            return {t.name: t for t in await c.list_tools()}

    tools = _run(go())
    assert tools["probe_ping"].annotations.read_only_hint is True
    # The upstream says wipe is read-only; the hub has not vouched for it.
    assert tools["probe_wipe"].annotations.read_only_hint is False


def test_rotation_and_expiry(stack):
    async def names(token):
        async with _client(stack, token) as c:
            return {t.name for t in await c.list_tools()}

    t = stack["tokens"]
    assert _run(names(t["full"])) == _run(names(t["full-new"]))
    for token in (t["expired"], "not-a-token-" + "x" * 40):
        r = httpx.post(
            stack["url"],
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            timeout=10,
        )
        assert r.status_code == 401


def test_session_is_not_an_identity(stack):
    """A session opened by one agent must not carry its rights."""
    hdr = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": "2025-06-18",
    }
    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "e2e", "version": "0"},
        },
    }
    call = {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "probe_wipe", "arguments": {}},
    }
    t = stack["tokens"]
    with httpx.Client(timeout=30) as h:
        full = {"authorization": f"Bearer {t['full']}"}
        r = h.post(stack["url"], json=init, headers={**hdr, **full})
        assert r.status_code == 200
        sid = r.headers.get("mcp-session-id")
        if not sid:
            pytest.skip("stateless server: no session to reuse")
        base = {**hdr, "mcp-session-id": sid}
        h.post(stack["url"], headers={**base, **full}, json={
            "jsonrpc": "2.0", "method": "notifications/initialized"})
        assert h.post(stack["url"], json=call, headers=base).status_code == 401
        narrow = {"authorization": f"Bearer {t['narrow']}"}
        r = h.post(stack["url"], json=call, headers={**base, **narrow})
        assert r.status_code in (401, 403, 404) or "not available" in r.text


def test_status_page(stack):
    url = stack["base"] + "/status"
    assert httpx.get(url, timeout=10).status_code == 401
    auth = base64.b64encode(f"ops:{STATUS_PW}".encode()).decode()
    r = httpx.get(url, headers={"Authorization": f"Basic {auth}"}, timeout=10)
    assert r.status_code == 200
    assert "2020-01-01 (expired)" in r.text
    assert "read-only" in r.text


def test_bridge_over_stdio(stack):
    token = stack["tokens"]["narrow"]
    env = {k: v for k, v in stack["env"].items() if k != "E2E_STATUS_PW"}
    env["E2E_HUB_TOKEN"] = token
    transport = StdioTransport(
        command=sys.executable,
        args=[str(ROOT / "hub.py"), "bridge", "--url", stack["url"],
              "--token-env", "E2E_HUB_TOKEN"],
        env=env,
        keep_alive=False,
    )

    async def go():
        async with Client(transport) as c:
            names = sorted(t.name for t in await c.list_tools())
            pong = _text(await c.call_tool("probe_ping", {}))
            denied = await c.call_tool("probe_wipe", {}, raise_on_error=False)
            return names, pong, denied

    names, pong, denied = _run(go())
    assert names == ["probe_headers", "probe_ping"]
    assert pong == "pong"
    assert denied.is_error


@pytest.mark.parametrize(
    ("url", "extra"),
    [
        ("http://hub.example.com/mcp", ["--allow-remote"]),
        ("https://hub.example.com/mcp", []),
    ],
)
def test_bridge_refuses_off_host_urls(stack, url, extra):
    env = {**stack["env"], "E2E_BRIDGE_TOKEN": "t" * 40}
    result = subprocess.run(
        [sys.executable, str(ROOT / "hub.py"), "bridge", "--url", url,
         "--token-env", "E2E_BRIDGE_TOKEN", *extra],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert result.returncode != 0
    assert "--allow-remote" in result.stderr
    assert result.stdout == ""


def _bridge_stdout(stack, url, token):
    """Initialize through the bridge; return (stdout lines, stderr)."""
    env = {**stack["env"], "E2E_BRIDGE_TOKEN": token}
    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "e2e", "version": "0"},
        },
    }
    listing = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    notice = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    stdin = "".join(json.dumps(m) + "\n" for m in (init, notice, listing))
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "hub.py"), "bridge", "--url", url,
         "--token-env", "E2E_BRIDGE_TOKEN"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    try:
        out, err = proc.communicate(stdin, timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    return [line for line in out.splitlines() if line.strip()], err


@pytest.mark.parametrize("case", ["bad-token", "no-hub"])
def test_bridge_stdout_is_only_json_rpc(stack, case):
    if case == "bad-token":
        url, token = stack["url"], "wrong-" + "x" * 40
    else:
        url, token = f"http://127.0.0.1:{_free_port()}/mcp", "y" * 40
    lines, err = _bridge_stdout(stack, url, token)
    assert lines, "the bridge should answer initialize"
    for line in lines:
        assert json.loads(line).get("jsonrpc") == "2.0", line
    assert token not in "\n".join(lines) + err


def test_audit_never_holds_arguments(stack):
    marker = "ARGUMENT-MARKER-" + secrets.token_hex(8)

    async def go():
        async with _client(stack, stack["tokens"]["full"]) as c:
            await c.call_tool("probe_fail", {"reason": marker},
                              raise_on_error=False)

    _run(go())
    audit = (stack["tmp"] / "state" / "audit.jsonl").read_text()
    assert '"tool": "probe_fail"' in audit
    assert marker not in audit


def test_reload_adds_an_agent(stack):
    t = stack["tokens"]
    late = f"""
[agents.late]
token_sha256 = "{_sha(t['late'])}"
groups = ["probe-read"]
"""
    stack["config"].write_text(_config(
        stack["probe_port"], stack["hub_port"], stack["tmp"] / "state", t,
        extra_agents=late))
    result = subprocess.run(
        [sys.executable, str(ROOT / "hub.py"), "reload", "--config",
         str(stack["config"])],
        capture_output=True, text=True, env=stack["env"], timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert '"decision": "allow"' in result.stdout

    async def go():
        async with _client(stack, t["late"]) as c:
            return sorted(t.name for t in await c.list_tools())

    assert _run(go()) == ["probe_headers", "probe_ping"]


def test_zz_log_holds_no_secrets(stack):
    # Runs last (name order): every earlier request has been logged.
    text = stack["log"].read_text()
    assert LEAK not in text
    for token in stack["tokens"].values():
        assert token not in text
    assert STATUS_PW not in text
