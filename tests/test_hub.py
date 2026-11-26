"""Unit tests for agent-hub. Offline: no secrets store, no network."""

import asyncio
import base64
import copy
import datetime as dt
import hashlib
import io
import logging
import sys
from pathlib import Path

import pytest
from fastmcp import Client, FastMCP
from fastmcp.server.auth.auth import AccessToken
from mcp.types import ToolAnnotations
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import hub  # noqa: E402

EXAMPLE = ROOT / "examples" / "hub.example.toml"


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _base_config(tmp_path=None):
    audit = (tmp_path or Path("/tmp")) / "agent-hub-unit-audit.jsonl"
    return {
        "hub": {
            "host": "127.0.0.1",
            "port": 18796,
            "path": "/mcp",
            "audit_log": str(audit),
        },
        "upstreams": {
            "todoist": {"url": "https://ai.todoist.net/mcp"},
            "mail": {"url": "https://mail.example.com/mcp"},
        },
        "groups": {
            "todo-read": {"access": "read", "allow": ["todoist_find"]},
            "todo-write": {"allow": ["todoist_add"]},
        },
        "agents": {
            "a1": {"token_sha256": _sha("tok-1"), "allow": ["todoist_find"]},
            "a2": {"token_sha256": _sha("tok-2"), "allow": ["mail_read"]},
        },
    }


def _error(fn):
    with pytest.raises(ValueError) as info:
        fn()
    return str(info.value)


@pytest.fixture
def as_agent(monkeypatch):
    """Make the hub's middleware see a chosen agent identity."""
    current = {"agent": "a1"}
    monkeypatch.setattr(
        hub, "get_access_token",
        lambda: AccessToken(token="hub", client_id=current["agent"],
                            scopes=[]),
    )
    return current


# -- Configuration ----------------------------------------------------------


def test_example_config_is_valid():
    config = hub.load_config(EXAMPLE)
    hub.validate_config(config)
    assert len(hub.agent_allow(config, config["agents"]["assistant"])) == 9
    assert len(hub.agent_allow(config, config["agents"]["ide"])) == 6
    assert hub.check(config, now=0) == 0


def test_validation_rejects_bad_configs():
    hub.validate_config(_base_config())

    dup = _base_config()
    dup["agents"]["a2"]["token_sha256"] = dup["agents"]["a1"]["token_sha256"]
    assert "share the same token_sha256" in _error(
        lambda: hub.validate_config(dup))

    upper = _base_config()
    upper["agents"]["a1"]["token_sha256"] = _sha("tok-1").upper()
    assert "64 lowercase hex" in _error(lambda: hub.validate_config(upper))

    bad_allow = _base_config()
    bad_allow["agents"]["a1"]["allow"].append("probe_headers")
    assert "upstream 'probe' is not configured" in _error(
        lambda: hub.validate_config(bad_allow))

    bad_up = _base_config()
    bad_up["upstreams"]["bad_name"] = {"url": "https://example.com/mcp"}
    assert "must not contain '_'" in _error(
        lambda: hub.validate_config(bad_up))

    bad_group = _base_config()
    bad_group["agents"]["a1"]["groups"] = ["nonexistent"]
    assert "unknown group 'nonexistent'" in _error(
        lambda: hub.validate_config(bad_group))

    cyclic = _base_config()
    cyclic["groups"] = {"g1": {"groups": ["g2"]}, "g2": {"groups": ["g1"]}}
    assert "group cycle" in _error(lambda: hub.validate_config(cyclic))


@pytest.mark.parametrize(
    ("section", "name", "key"),
    [
        ("agents", "a1", "read-only"),
        ("agents", "a1", "readonly"),
        ("groups", "todo-read", "acess"),
        ("upstreams", "todoist", "header"),
    ],
)
def test_unknown_keys_are_errors(section, name, key):
    # A misspelt security setting must not be silently ignored.
    config = _base_config()
    config[section][name][key] = True
    assert "unknown keys" in _error(lambda: hub.validate_config(config))


def test_unknown_hub_and_top_level_keys_are_errors():
    config = _base_config()
    config["hub"]["prot"] = 1
    assert "[hub] has unknown keys: prot" in _error(
        lambda: hub.validate_config(config))
    config = _base_config()
    config["agent"] = {}
    assert "config has unknown keys: agent" in _error(
        lambda: hub.validate_config(config))


def test_read_only_agents_and_read_groups():
    config = _base_config()
    config["agents"]["a1"] = {
        "token_sha256": _sha("tok-1"),
        "groups": ["todo-read"],
        "read_only": True,
    }
    hub.validate_config(config)
    assert hub.read_tools(config) == {"todoist_find"}

    config["agents"]["a1"]["groups"].append("todo-write")
    assert "outside every read group: todoist_add" in _error(
        lambda: hub.validate_config(config))
    # Even unvalidated, a read-only agent gets only read tools.
    assert hub.agent_allow(config, config["agents"]["a1"]) == {
        "todoist_find"}

    nested = _base_config()
    nested["groups"]["todo-read"]["groups"] = ["todo-write"]
    assert "is not a read group" in _error(
        lambda: hub.validate_config(nested))

    bad_access = _base_config()
    bad_access["groups"]["todo-read"]["access"] = "readonly"
    assert "access must be" in _error(
        lambda: hub.validate_config(bad_access))


def test_token_lists_and_expiry_validation():
    config = _base_config()
    config["agents"]["a1"]["token_sha256"] = [_sha("old"), _sha("new")]
    config["agents"]["a1"]["expires"] = dt.date(2030, 1, 1)
    hub.validate_config(config)

    config["agents"]["a2"]["token_sha256"] = [_sha("new")]
    assert "share the same token_sha256" in _error(
        lambda: hub.validate_config(config))

    empty = _base_config()
    empty["agents"]["a1"]["token_sha256"] = []
    assert "needs token_sha256" in _error(lambda: hub.validate_config(empty))

    as_string = _base_config()
    as_string["agents"]["a1"]["expires"] = "2030-01-01"
    assert "TOML date" in _error(lambda: hub.validate_config(as_string))


def test_oauth_upstream_needs_key_and_port():
    config = _base_config()
    config["upstreams"]["sentry"] = {
        "url": "https://mcp.sentry.dev/mcp", "auth": "oauth"}
    assert "callback_port" in _error(lambda: hub.validate_config(config))
    config["upstreams"]["sentry"]["callback_port"] = 18801
    assert "oauth_key" in _error(lambda: hub.validate_config(config))
    config["hub"]["oauth_key"] = "env:KEY"
    hub.validate_config(config)


def test_paths_resolve_against_config_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    cfg = tmp_path / "conf" / "hub.toml"
    cfg.parent.mkdir()
    cfg.write_text('[hub]\naudit_log = "logs/audit.jsonl"\n')
    config = hub.load_config(cfg)
    h = config["hub"]
    assert h["audit_log"] == str(tmp_path / "conf" / "logs" / "audit.jsonl")
    assert h["state_dir"] == str(tmp_path / "state" / "agent-hub")
    assert h["oauth_dir"] == str(tmp_path / "state" / "agent-hub" / "oauth")
    assert (h["host"], h["port"], h["path"]) == ("127.0.0.1", 18797, "/mcp")
    # Resolving again (build() does) changes nothing.
    before = copy.deepcopy(config)
    hub.resolve_paths(config, Path("/elsewhere"))
    assert config == before


def test_default_config_path(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENT_HUB_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert hub.default_config_path() == tmp_path / "agent-hub" / "hub.toml"
    monkeypatch.setenv("AGENT_HUB_CONFIG", str(tmp_path / "work.toml"))
    assert hub.default_config_path() == tmp_path / "work.toml"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda c: c.pop("upstreams"), "at least one [upstreams.NAME]"),
        (lambda c: c.__setitem__("agents", []), "[agents] must be a table"),
        (lambda c: c["hub"].__setitem__("status", {"user": "x"}),
         "[hub.status] needs a password"),
        (lambda c: c["hub"].__setitem__("port", "18797"),
         "[hub] port must be an integer"),
        (lambda c: c["hub"].__setitem__("port", 70000), "between 1 and"),
        (lambda c: c["hub"].__setitem__("path", "mcp"), "start with /"),
        (lambda c: c["agents"]["a1"].__setitem__("allow", "todoist_find"),
         "allow must be a list of strings"),
        (lambda c: c["groups"]["todo-read"].__setitem__("groups", "x"),
         "groups must be a list of strings"),
        (lambda c: c["groups"]["todo-write"].__setitem__("access", "write"),
         "access must be"),
        (lambda c: c["agents"]["a1"].__setitem__("token_sha256", 5),
         "token_sha256 must be a list of strings"),
        (lambda c: c["agents"]["a1"].__setitem__(
            "token_sha256", [_sha("x"), 5]),
         "token_sha256 must be a list of strings"),
    ],
)
def test_shape_errors_are_validation_errors(mutate, message):
    # Each of these used to surface as a KeyError or a character-by-
    # character iteration instead of a clear message.
    config = _base_config()
    mutate(config)
    assert message in _error(lambda: hub.validate_config(config))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('hub = "x"\n', "[hub] must be a table"),
        ("[hub]\nstate_dir = 5\n", "[hub] state_dir must be a string"),
    ],
)
def test_malformed_hub_table_fails_cleanly(tmp_path, text, message):
    cfg = tmp_path / "hub.toml"
    cfg.write_text(text)
    assert message in _error(lambda: hub.load_config(cfg))


def test_missing_groups_and_agents_default_to_empty():
    config = _base_config()
    del config["groups"], config["agents"]
    hub.validate_config(config)
    assert config["agents"] == {} and config["groups"] == {}


def test_env_secret_can_be_referenced_twice(monkeypatch):
    monkeypatch.setattr(hub, "_SECRETS", {})
    monkeypatch.setenv("TWICE_USED_KEY", "value-for-two-upstreams")
    first = hub.resolve_value("Bearer ${TWICE_USED_KEY}")
    second = hub.resolve_value("env:TWICE_USED_KEY")
    assert first == "Bearer value-for-two-upstreams"
    assert second == "value-for-two-upstreams"
    assert "TWICE_USED_KEY" not in hub.os.environ


def test_check_warns_about_literal_secrets(capsys):
    config = _base_config()
    config["hub"]["status"] = {"password": "hunter2-literal"}
    config["upstreams"]["todoist"]["headers"] = {
        "Authorization": "Bearer abc", "X-Env": "env:OK", "X-Sub": "${OK}"}
    config["upstreams"]["todoist"]["url"] = "https://t.example.com/mcp?k=raw"
    config["upstreams"]["mail"]["url"] = "https://m.example.com/mcp?k=${K}"
    assert hub.check(config) == 0
    err = capsys.readouterr().err
    assert "[hub.status] password is a literal" in err
    assert "header Authorization is a literal" in err
    assert "upstream 'todoist' url query is a literal" in err
    assert "X-Env" not in err and "X-Sub" not in err
    assert "'mail'" not in err


def test_check_reports_expired_agents(capsys):
    config = _base_config()
    config["agents"]["a1"]["expires"] = dt.date(2020, 1, 1)
    assert hub.check(config) == 1
    out = capsys.readouterr().out
    assert "a1: 1 tools, expires 2020-01-01 (expired)" in out
    assert "a2: 1 tools, expires never" in out


# -- Tokens -----------------------------------------------------------------


def test_tokens_rotation_and_expiry(tmp_path):
    clock = {"now": dt.datetime(2027, 1, 10).timestamp()}
    audit = hub.Audit(tmp_path / "audit.jsonl")
    agents = {
        "a1": {
            "token_sha256": [_sha("old-token"), _sha("new-token")],
            "expires": dt.date(2027, 2, 1),
        },
        "a2": {"token_sha256": _sha("other-token")},
    }
    tokens = hub.HubTokens(agents, audit, clock=lambda: clock["now"])

    async def who(token):
        result = await tokens.verify_token(token)
        return result.client_id if result else None

    assert asyncio.run(who("old-token")) == "a1"
    assert asyncio.run(who("new-token")) == "a1"
    assert asyncio.run(who("other-token")) == "a2"
    assert asyncio.run(who("wrong-token")) is None

    clock["now"] = dt.datetime(2027, 2, 1).timestamp()
    assert asyncio.run(who("new-token")) is None
    assert asyncio.run(who("other-token")) == "a2"
    # Repeated attempts write one audit line per minute.
    asyncio.run(who("old-token"))
    expired = [e for e in audit.tail(10) if e.get("error") == "TokenExpired"]
    assert len(expired) == 1 and expired[0]["agent"] == "a1"
    clock["now"] += 61
    asyncio.run(who("old-token"))
    expired = [e for e in audit.tail(10) if e.get("error") == "TokenExpired"]
    assert len(expired) == 2


def test_expiry_timestamp_forms():
    day = dt.date(2027, 3, 1)
    assert hub.expiry_timestamp(day) == dt.datetime(2027, 3, 1).timestamp()
    aware = dt.datetime(2027, 3, 1, 12, tzinfo=dt.UTC)
    assert hub.expiry_timestamp(aware) == aware.timestamp()
    assert hub.expiry_timestamp(None) is None


def test_hash_token(capsys):
    token = "x" * 40

    class Stream(io.StringIO):
        def isatty(self):
            return False

    assert hub.hash_token(Stream(token + "\n")) == 0
    assert capsys.readouterr().out.strip() == _sha(token)
    assert hub.hash_token(Stream("short\n")) == 1
    assert capsys.readouterr().out == ""


def test_bridge_url_guard():
    assert hub.bridge_url_ok("http://127.0.0.1:18797/mcp")
    assert hub.bridge_url_ok("http://localhost:18797/mcp")
    assert hub.bridge_url_ok("http://[::1]:18797/mcp")
    assert hub.bridge_url_ok("https://127.0.0.1:18797/mcp")
    # Off this machine only with --allow-remote, and only over https.
    assert not hub.bridge_url_ok("https://hub.example.com/mcp")
    assert hub.bridge_url_ok("https://hub.example.com/mcp", allow_remote=True)
    assert not hub.bridge_url_ok("http://hub.example.com/mcp", True)
    assert not hub.bridge_url_ok("http://10.0.0.5:18797/mcp", True)
    assert not hub.bridge_url_ok("ftp://127.0.0.1/mcp", True)
    assert not hub.bridge_url_ok("https://127.0.0.1.example.com/mcp")


# -- Logging ----------------------------------------------------------------


def test_secret_redactor():
    hub.REDACTOR.install()
    secret = "subl_secret_val+123/456"
    hub.REDACTOR.add(secret)
    scrubbed = hub.REDACTOR.scrub(
        f"Server error for url 'https://mcp.example.com/mcp?token={secret}' "
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"
    )
    assert secret not in scrubbed
    assert "abcdefghijklmnopqrstuvwxyz" not in scrubbed
    assert "token=<REDACTED>" in scrubbed
    assert "Bearer <REDACTED>" in scrubbed

    records: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(self.format(record))

    lg = logging.getLogger("agent_hub_test_redactor")
    lg.propagate = False
    lg.setLevel(logging.DEBUG)
    handler = Capture()
    lg.addHandler(handler)
    try:
        try:
            raise RuntimeError(
                "502 Bad Gateway for url "
                f"'https://mcp.example.com/mcp?token={secret}'"
            )
        except RuntimeError:
            lg.error("Failed calling https://mcp.example.com/mcp?token=%s",
                     secret, exc_info=True)
    finally:
        lg.removeHandler(handler)

    assert len(records) == 1
    assert secret not in records[0]
    assert "token=<REDACTED>" in records[0]


def test_redactor_keeps_uvicorn_access_args():
    """uvicorn's AccessFormatter unpacks a 5-tuple from record.args."""
    from uvicorn.logging import AccessFormatter

    hub.REDACTOR.install()
    fmt = AccessFormatter(
        '%(client_addr)s - "%(request_line)s" %(status_code)s',
        use_colors=False)
    template = '%s - "%s %s HTTP/%s" %d'

    def access(path):
        return logging.getLogRecordFactory()(
            "uvicorn.access", logging.INFO, __file__, 1, template,
            ("127.0.0.1:5000", "POST", path, "1.1", 200), None,
        )

    plain = access("/mcp")
    assert plain.args == ("127.0.0.1:5000", "POST", "/mcp", "1.1", 200)
    assert fmt.format(plain) == '127.0.0.1:5000 - "POST /mcp HTTP/1.1" 200 OK'

    queried = access("/mcp?token=LEAKME999")
    assert isinstance(queried.args, tuple) and len(queried.args) == 5
    out = fmt.format(queried)
    assert "LEAKME999" not in out
    assert out == (
        '127.0.0.1:5000 - "POST /mcp?token=<REDACTED> HTTP/1.1" 200 OK')


# -- Audit ------------------------------------------------------------------


def test_audit_tail_and_rotation(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit = hub.Audit(log_path, max_recent=3, max_bytes=120, backups=2)
    for i in range(6):
        audit.write(agent="a1", method="tools/call", tool=f"todoist_t{i}",
                    decision="allow")
    recent = audit.tail(10)
    assert [e["tool"] for e in recent] == [
        "todoist_t5", "todoist_t4", "todoist_t3"]
    assert log_path.exists()
    assert Path(f"{log_path}.1").exists()
    audit2 = hub.Audit(log_path, max_recent=10)
    assert any(e["tool"] == "todoist_t5" for e in audit2.tail(10))


# -- Upstreams and policy ---------------------------------------------------


def test_static_proxy_disables_server_initiated_callbacks():
    proxy, shared = hub.upstream_proxy(
        "todoist", {"url": "http://127.0.0.1:1/mcp"}, store=None
    )
    assert shared is None
    assert proxy._mask_error_details is True
    assert proxy.provider_error_strategy == "raise"
    client = proxy.client_factory()
    assert client._transport_options.forward_incoming_headers is False
    assert client._session_kwargs.get("sampling_callback") is None
    assert client._session_kwargs.get("list_roots_callback") is None
    assert client._session_kwargs.get("elicitation_callback") is None


def test_shared_client_recovery():
    created = []

    class FakeClient:
        def __init__(self):
            self.connected = False
            self.closed = False
            created.append(self)

        def is_connected(self):
            return self.connected

        async def __aenter__(self):
            self.connected = True
            return self

        async def close(self):
            self.connected = False
            self.closed = True

    async def run():
        sc = hub.SharedClient(FakeClient)
        c1 = await sc()
        c2 = await sc()
        assert c1 is c2 and len(created) == 1
        await sc.reset()
        assert c1.closed is True
        c3 = await sc()
        assert c3 is not c1 and len(created) == 2

    asyncio.run(run())


def _mcp_tool(name, annotations=None):
    from mcp.types import Tool as McpTool

    return McpTool(
        name=name,
        description=name,
        input_schema={"type": "object", "properties": {}},
        annotations=annotations,
    )


class _FakeUpstream:
    """Stands in for an upstream client inside FastMCPProxy."""

    def __init__(self, tools):
        self.tools = tools

    async def __call__(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    @property
    def protocol_version(self):
        return "2025-06-18"

    async def list_tools(self):
        return self.tools


def test_upstream_gate_scoping_and_health(as_agent):
    calls = {"good": 0, "bad": 0}
    good_backend = FastMCP("good")

    @good_backend.tool
    def ping() -> str:
        calls["good"] += 1
        return "pong"

    class FlakyClient(_FakeUpstream):
        """Lists fine; fails with HTTP 502 and a secret URL on call."""

        def __init__(self):
            super().__init__([_mcp_tool("explode")])
            self.reset_called = False

        async def call_tool_mcp(self, name, arguments=None, meta=None):
            raise RuntimeError(
                "Server error '502 Bad Gateway' for url "
                "'https://mcp.example.com/mcp?token=LEAKME999'"
            )

        async def reset(self):
            self.reset_called = True

    class FailingClient:
        def __init__(self):
            self.reset_called = False

        async def __call__(self):
            calls["bad"] += 1
            raise RuntimeError(
                "502 Bad Gateway for url "
                "'https://mcp.example.com/mcp?token=LEAKME999'"
            )

        async def reset(self):
            self.reset_called = True

    flaky_shared = FlakyClient()
    failing_shared = FailingClient()
    health = hub.Health(["good", "flaky", "bad"])
    good_proxy = hub.create_proxy(
        Client(good_backend), name="good", mask_error_details=True,
        provider_error_strategy="raise",
    )
    flaky_proxy = hub.FastMCPProxy(
        client_factory=flaky_shared, name="flaky", mask_error_details=True,
        provider_error_strategy="raise",
    )
    bad_proxy = hub.FastMCPProxy(
        client_factory=failing_shared, name="bad", mask_error_details=True,
        provider_error_strategy="raise",
    )
    good_proxy.add_middleware(hub.UpstreamGate("good", {"a1", "a2"}, health))
    flaky_proxy.add_middleware(hub.UpstreamGate(
        "flaky", {"a1", "a2"}, health, shared_client=flaky_shared))
    bad_proxy.add_middleware(hub.UpstreamGate(
        "bad", {"a2"}, health, shared_client=failing_shared))

    parent = FastMCP("test-hub", mask_error_details=True)
    parent.mount(good_proxy, namespace="good")
    parent.mount(flaky_proxy, namespace="flaky")
    parent.mount(bad_proxy, namespace="bad")

    async def run():
        async with Client(parent) as c:
            # a1 does not allow `bad`, so `bad` must never be queried.
            tools = await c.list_tools()
            assert sorted(t.name for t in tools) == [
                "flaky_explode", "good_ping"]
            assert calls["bad"] == 0
            assert health.state["good"]["ok"] is not None
            assert health.state["bad"]["error"] is None

            # A transport error must not leak the URL token to the client,
            # and must reset the OAuth SharedClient.
            res = await c.call_tool("flaky_explode", {}, raise_on_error=False)
            txt = "".join(getattr(x, "text", "") for x in res.content)
            assert res.is_error is True
            assert "LEAKME999" not in txt
            assert "token=" not in txt
            assert flaky_shared.reset_called is True

            # a2 allows `bad`: it is queried, fails, is recorded, and the
            # healthy upstreams still list.
            as_agent["agent"] = "a2"
            tools2 = await c.list_tools()
            assert sorted(t.name for t in tools2) == [
                "flaky_explode", "good_ping"]
            assert calls["bad"] > 0
            assert health.state["bad"]["error"] is not None
            assert failing_shared.reset_called is True

    asyncio.run(run())


def test_upstream_gate_retries_stale_list(as_agent):
    class StaleOnceClient(_FakeUpstream):
        """First list_tools fails (stale session); after reset it works."""

        def __init__(self):
            super().__init__([_mcp_tool("GetTags")])
            self.stale = True
            self.resets = 0
            self.lists = 0

        async def list_tools(self):
            self.lists += 1
            if self.stale:
                raise RuntimeError("Connection closed")
            return self.tools

        async def reset(self):
            self.resets += 1
            self.stale = False

    shared = StaleOnceClient()
    health = hub.Health(["oauthy"])
    proxy = hub.FastMCPProxy(
        client_factory=shared, name="oauthy", mask_error_details=True,
        provider_error_strategy="raise",
    )
    proxy.add_middleware(
        hub.UpstreamGate("oauthy", {"a1"}, health, shared_client=shared))
    parent = FastMCP("test-hub", mask_error_details=True)
    parent.mount(proxy, namespace="oauthy")

    async def run():
        async with Client(parent) as c:
            tools = await c.list_tools()
            assert [t.name for t in tools] == ["oauthy_GetTags"]
            assert shared.resets == 1 and shared.lists == 2
            assert health.state["oauthy"]["error"] is None

    asyncio.run(run())


def test_policy_owns_read_only_hints(tmp_path, as_agent):
    """The hub's classification replaces the upstream's readOnlyHint."""
    upstream = _FakeUpstream([
        # Claims read-only, but the hub has not vouched for it.
        _mcp_tool("add", ToolAnnotations(
            read_only_hint=True, destructive_hint=True)),
        # Claims nothing; the hub classifies it as read.
        _mcp_tool("find"),
        # Claims writes; the hub classifies it as read.
        _mcp_tool("get", ToolAnnotations(read_only_hint=False)),
    ])
    proxy = hub.FastMCPProxy(
        client_factory=upstream, name="todoist", mask_error_details=True,
        provider_error_strategy="raise",
    )
    parent = FastMCP("test-hub", mask_error_details=True)
    parent.mount(proxy, namespace="todoist")
    audit = hub.Audit(tmp_path / "audit.jsonl")
    allow = {"a1": {"todoist_add", "todoist_find", "todoist_get"}}
    reads = {"todoist_find", "todoist_get"}
    parent.add_middleware(hub.Policy(allow, reads, audit, hub.Health([])))

    async def run():
        async with Client(parent) as c:
            return {t.name: t for t in await c.list_tools()}

    tools = asyncio.run(run())
    hints = {n: t.annotations.read_only_hint for n, t in tools.items()}
    assert hints == {
        "todoist_add": False, "todoist_find": True, "todoist_get": True}
    # An unvouched tool is destructive and not idempotent, whatever the
    # upstream said.
    add = tools["todoist_add"].annotations
    assert add.destructive_hint is True and add.idempotent_hint is False


def test_unvouched_tool_claiming_harmless_is_marked_destructive(
        tmp_path, as_agent):
    upstream = _FakeUpstream([
        _mcp_tool("purge", ToolAnnotations(
            title="Purge", read_only_hint=True, destructive_hint=False,
            idempotent_hint=True, open_world_hint=False)),
    ])
    proxy = hub.FastMCPProxy(
        client_factory=upstream, name="todoist", mask_error_details=True,
        provider_error_strategy="raise",
    )
    parent = FastMCP("test-hub", mask_error_details=True)
    parent.mount(proxy, namespace="todoist")
    parent.add_middleware(hub.Policy(
        {"a1": {"todoist_purge"}}, set(), hub.Audit(tmp_path / "a.jsonl"),
        hub.Health([])))

    async def run():
        async with Client(parent) as c:
            return (await c.list_tools())[0].annotations

    a = asyncio.run(run())
    assert (a.read_only_hint, a.destructive_hint, a.idempotent_hint) == (
        False, True, False)
    # Title and openWorldHint are not safety claims; they pass through.
    assert a.title == "Purge" and a.open_world_hint is False


def test_policy_denies_and_audits(tmp_path, as_agent):
    backend = FastMCP("todoist")

    @backend.tool
    def find() -> str:
        return "found"

    @backend.tool
    def add() -> str:
        return "added"

    parent = FastMCP("test-hub", mask_error_details=True)
    parent.mount(backend, namespace="todoist")
    audit = hub.Audit(tmp_path / "audit.jsonl")
    parent.add_middleware(hub.Policy(
        {"a1": {"todoist_find"}}, {"todoist_find"}, audit, hub.Health([])))

    async def run():
        async with Client(parent) as c:
            names = [t.name for t in await c.list_tools()]
            assert names == ["todoist_find"]
            ok = await c.call_tool("todoist_find", {})
            assert ok.content[0].text == "found"
            denied = await c.call_tool("todoist_add", {}, raise_on_error=False)
            assert denied.is_error
            assert denied.content[0].text == hub.DENIED
            unknown = await c.call_tool(
                "todoist_nope", {}, raise_on_error=False)
            assert unknown.content[0].text == hub.DENIED

    asyncio.run(run())
    events = audit.tail(10)
    deny = next(e for e in events if e.get("tool") == "todoist_add")
    assert deny["decision"] == "deny" and deny["agent"] == "a1"
    assert all("arguments" not in e for e in events)


# -- Assembly, reload and status page --------------------------------------


def _write_config(path, audit_path, agents_block):
    path.write_text(
        f'[hub]\naudit_log = "{audit_path}"\nstate_dir = "state"\n'
        '[hub.status]\nuser = "ops"\npassword = "env:TEST_STATUS_PW"\n'
        '[upstreams.todoist]\nurl = "http://127.0.0.1:1/mcp"\n'
        '[groups.r]\naccess = "read"\nallow = ["todoist_find"]\n'
        f"{agents_block}"
    )


def test_live_policy_reload(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_STATUS_PW", "pw-for-tests")
    cfg_path = tmp_path / "hub.toml"
    audit_path = tmp_path / "audit.jsonl"
    tok1, tok2 = "token-one-secret", "token-two-secret"
    _write_config(cfg_path, audit_path,
                  f'[agents.a1]\ntoken_sha256 = "{_sha(tok1)}"\n'
                  'groups = ["r"]\n')
    server = hub.build(hub.load_config(cfg_path), config_path=cfg_path)

    async def who(token):
        result = await server.auth.verify_token(token)
        return result.client_id if result else None

    assert asyncio.run(who(tok1)) == "a1"
    assert asyncio.run(who(tok2)) is None

    _write_config(cfg_path, audit_path,
                  f'[agents.a2]\ntoken_sha256 = "{_sha(tok2)}"\n'
                  'groups = ["r"]\nread_only = true\n')
    assert server.reload_policy() is True
    assert asyncio.run(who(tok1)) is None
    assert asyncio.run(who(tok2)) == "a2"

    # An invalid edit leaves the running policy alone.
    cfg_path.write_text("[agents.broken]\ntoken_sha256 = 'not-a-hash'\n")
    assert server.reload_policy() is False
    assert asyncio.run(who(tok2)) == "a2"


def test_reload_cannot_give_a_read_only_agent_a_write_tool(
        tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_STATUS_PW", "pw-for-tests")
    cfg_path = tmp_path / "hub.toml"
    audit_path = tmp_path / "audit.jsonl"
    tok = "read-only-agent-token"
    agent = (f'[agents.ro]\ntoken_sha256 = "{_sha(tok)}"\n'
             'groups = ["r"]\nread_only = true\n')
    _write_config(cfg_path, audit_path, agent)
    server = hub.build(hub.load_config(cfg_path), config_path=cfg_path)
    policy = next(m for m in server.middleware if isinstance(m, hub.Policy))
    assert policy.allow["ro"] == {"todoist_find"}

    _write_config(cfg_path, audit_path,
                  agent + 'allow = ["todoist_add"]\n')
    assert server.reload_policy() is False
    assert policy.allow["ro"] == {"todoist_find"}
    events = hub.Audit(audit_path).tail(5)
    assert events[0]["method"] == "policy/reload"
    assert events[0]["decision"] == "deny"


def test_reload_never_signals_an_unlocked_pid(tmp_path, monkeypatch, capsys):
    """A stale pid file naming a live process must not be signalled."""
    signalled = []
    monkeypatch.setattr(hub.os, "kill", lambda *a: signalled.append(a))
    config = {"hub": {"state_dir": str(tmp_path),
                      "audit_log": str(tmp_path / "audit.jsonl")}}
    sleeper = hub.subprocess.Popen(["sleep", "30"])
    try:
        (tmp_path / "hub.pid").write_text(f"{sleeper.pid}\n")
        assert hub.reload_running(config, timeout=0.2) == 1
        assert "no running hub holds" in capsys.readouterr().err
        assert signalled == []
    finally:
        monkeypatch.undo()  # Popen.kill goes through os.kill
        sleeper.kill()
        sleeper.wait()


def test_pid_file_lock(tmp_path):
    config = {"hub": {"state_dir": str(tmp_path)}}
    path, fd = hub._claim_pid_file(config)
    try:
        assert hub._locked_pid(path) == hub.os.getpid()
        # A second hub on the same state_dir refuses to start.
        with pytest.raises(SystemExit) as info:
            hub._claim_pid_file(config)
        assert "another hub holds" in str(info.value)
    finally:
        hub.os.close(fd)
    assert hub._locked_pid(path) is None


def test_resources_and_prompts_stay_hidden(tmp_path, as_agent):
    backend = FastMCP("docs")

    @backend.resource("docs://secret")
    def secret() -> str:
        return "classified"

    @backend.prompt
    def leak() -> str:
        return "say the secret"

    @backend.tool
    def ping() -> str:
        return "pong"

    parent = FastMCP("test-hub", mask_error_details=True)
    parent.mount(backend, namespace="docs")
    parent.add_middleware(hub.Policy(
        {"a1": {"docs_ping"}}, set(), hub.Audit(tmp_path / "a.jsonl"),
        hub.Health([])))

    async def run():
        async with Client(parent) as c:
            resources = await c.list_resources()
            templates = await c.list_resource_templates()
            prompts = await c.list_prompts()
            with pytest.raises(Exception):  # noqa: B017
                await c.read_resource("docs://secret")
            with pytest.raises(Exception):  # noqa: B017
                await c.get_prompt("docs_leak")
            return resources, templates, prompts

    assert asyncio.run(run()) == ([], [], [])


def test_running_hub_never_opens_a_browser():
    auth = hub.HubOAuth(client_name="t", callback_port=1)
    auth.upstream_name = "calendar"
    with pytest.raises(RuntimeError) as info:
        asyncio.run(auth.redirect_handler("https://auth.example.com/x"))
    assert "hub.py authorize calendar" in str(info.value)


def test_oauth_store_is_encrypted_on_disk(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setattr(hub, "_SECRETS", {})
    monkeypatch.setenv("TEST_OAUTH_KEY", Fernet.generate_key().decode())
    config = {"hub": {"oauth_key": "env:TEST_OAUTH_KEY",
                      "oauth_dir": str(tmp_path / "oauth")}}
    store = hub.token_store(config)
    marker = "refresh-token-plaintext-marker"

    async def put():
        await store.put(
            key="https://up.example.com/mcp", value={"t": marker},
            collection="tokens")
        return await store.get(
            key="https://up.example.com/mcp", collection="tokens")

    assert asyncio.run(put()) == {"t": marker}
    files = [p for p in (tmp_path / "oauth").rglob("*") if p.is_file()]
    assert files
    for p in files:
        assert marker.encode() not in p.read_bytes()


def test_status_page_auth_and_content(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_STATUS_PW", "pw-for-tests")
    cfg_path = tmp_path / "hub.toml"
    _write_config(cfg_path, tmp_path / "audit.jsonl",
                  f'[agents.a1]\ntoken_sha256 = "{_sha("t" * 40)}"\n'
                  'groups = ["r"]\nexpires = 2020-01-01\n')
    server = hub.build(hub.load_config(cfg_path), config_path=cfg_path)

    def basic(user, password):
        raw = base64.b64encode(f"{user}:{password}".encode()).decode()
        return {"Authorization": f"Basic {raw}"}

    with TestClient(server.http_app()) as client:
        assert client.get("/status").status_code == 401
        wrong_user = client.get(
            "/status", headers=basic("admin", "pw-for-tests"))
        assert wrong_user.status_code == 401
        wrong_pw = client.get("/status", headers=basic("ops", "nope"))
        assert wrong_pw.status_code == 401
        ok = client.get("/status", headers=basic("ops", "pw-for-tests"))
        assert ok.status_code == 200
        assert "2020-01-01 (expired)" in ok.text
        assert "todoist_find" in ok.text


# -- Upstream OAuth corrections ------------------------------------------

_MCP = "https://mcp.example.com/mcp"
_AS = "https://auth.example.com"


def _oauth_with_tokens(transport):
    from key_value.aio.stores.memory import MemoryStore
    from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

    spec = {"url": _MCP, "callback_port": 1, "scopes": ["mcp:read"]}
    auth = hub.oauth_for("cal", spec, MemoryStore(), "t", interactive=False)
    auth._bind(_MCP)
    auth.discovery_transport = transport
    auth.context.client_info = OAuthClientInformationFull(
        client_id="client-1", redirect_uris=["http://localhost:1/callback"])
    auth.context.current_tokens = OAuthToken(
        access_token="a", token_type="Bearer", refresh_token="r",
        expires_in=1)
    return auth


def _metadata_server(seen):
    import httpx2

    def handle(request):
        url = str(request.url)
        seen.append(url)
        if url == ("https://mcp.example.com/.well-known/"
                   "oauth-protected-resource/mcp"):
            return httpx2.Response(200, json={
                "resource": _MCP, "authorization_servers": [_AS]})
        if url == f"{_AS}/.well-known/oauth-authorization-server":
            return httpx2.Response(200, json={
                "issuer": _AS,
                "authorization_endpoint": f"{_AS}/oauth/authorize/",
                "token_endpoint": f"{_AS}/oauth/token/",
                "response_types_supported": ["code"],
            })
        return httpx2.Response(404)

    return httpx2.MockTransport(handle)


@pytest.mark.filterwarnings("ignore:Using in-memory token storage")
def test_refresh_after_restart_uses_the_discovered_token_endpoint():
    # A restarted hub holds tokens but no metadata; the SDK alone would
    # post the refresh to https://mcp.example.com/token.
    seen = []
    auth = _oauth_with_tokens(_metadata_server(seen))
    assert auth.context.oauth_metadata is None
    request = asyncio.run(auth._refresh_token())
    assert str(request.url) == f"{_AS}/oauth/token/"
    assert seen and all(u.startswith("https://") for u in seen)


@pytest.mark.filterwarnings("ignore:Using in-memory token storage")
def test_refresh_falls_back_when_discovery_finds_nothing():
    import httpx2

    auth = _oauth_with_tokens(
        httpx2.MockTransport(lambda request: httpx2.Response(404)))
    request = asyncio.run(auth._refresh_token())
    assert str(request.url) == "https://mcp.example.com/token"


@pytest.mark.filterwarnings("ignore:Using in-memory token storage")
def test_sign_in_requests_only_the_configured_scopes(monkeypatch):
    # The SDK sets the scope to everything the server advertises just
    # before it builds the authorization URL.
    captured = {}

    async def fake_perform(self):
        captured["scope"] = self.context.client_metadata.scope
        return "done"

    monkeypatch.setattr(hub.OAuth, "_perform_authorization", fake_perform)
    for interactive in (True, False):
        auth = hub.oauth_for(
            "cal", {"url": _MCP, "callback_port": 1,
                    "scopes": ["mcp:read"]},
            None, "t", interactive=interactive)
        auth._bind(_MCP)
        auth.context.client_metadata.scope = "mcp:read mcp:write"
        assert asyncio.run(auth._perform_authorization()) == "done"
        assert captured["scope"] == "mcp:read"
