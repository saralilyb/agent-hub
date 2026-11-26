"""agent-hub: one MCP endpoint for several agents.

The hub holds upstream credentials. Each agent holds only its own hub
token. The hub maps the token to an agent name, shows and allows only that
agent's tools, and writes an argument-free audit line for every list and
call.

Usage:
    hub.py serve      [--config FILE]   run the hub
    hub.py check      [--config FILE]   validate the config, show agents
    hub.py reload     [--config FILE]   reload [agents]/[groups] (SIGHUP)
    hub.py authorize  UPSTREAM [--config FILE]
                                        one-time OAuth sign-in (browser)
    hub.py tools      [UPSTREAM] [--config FILE]
                                        list upstream tools and their claims
    hub.py hash-token                   SHA-256 of a token read from stdin
    hub.py bridge --url URL (--token-env NAME | --keychain SERVICE)
                  [--account NAME] [--allow-remote]
                                        stdio-to-hub bridge for one agent

The config file is --config, else $AGENT_HUB_CONFIG, else
$XDG_CONFIG_HOME/agent-hub/hub.toml (~/.config/agent-hub/hub.toml).
"""

import os

# The hub must never hold a 1Password service-account token or other OP_*
# settings. The agent-hub script strips them before exec; this is a second
# guard.
for _name in [n for n in os.environ if n.startswith("OP_")]:
    os.environ.pop(_name, None)
# No update checks or other calls home.
os.environ.setdefault("FASTMCP_CHECK_FOR_UPDATES", "off")

import argparse  # noqa: E402
import asyncio  # noqa: E402
import base64  # noqa: E402
import collections  # noqa: E402
import datetime as dt  # noqa: E402
import fcntl  # noqa: E402
import getpass  # noqa: E402
import hashlib  # noqa: E402
import hmac  # noqa: E402
import html  # noqa: E402
import ipaddress  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import re  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import tomllib  # noqa: E402
import traceback  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from pathlib import Path  # noqa: E402
from urllib.parse import quote, urlsplit  # noqa: E402

from cryptography.fernet import Fernet  # noqa: E402
from fastmcp import Client, FastMCP  # noqa: E402
from fastmcp.client.auth import OAuth  # noqa: E402
from fastmcp.client.transports import StreamableHttpTransport  # noqa: E402
from fastmcp.exceptions import ToolError, ValidationError  # noqa: E402
from fastmcp.server import create_proxy  # noqa: E402
from fastmcp.server.auth.auth import AccessToken, TokenVerifier  # noqa: E402
from fastmcp.server.dependencies import get_access_token  # noqa: E402
from fastmcp.server.middleware import Middleware  # noqa: E402
from fastmcp.server.providers.proxy import (  # noqa: E402
    FastMCPProxy,
    ProxyClient,
)
from key_value.aio.stores.filetree import (  # noqa: E402
    FileTreeStore,
    FileTreeV1CollectionSanitizationStrategy,
    FileTreeV1KeySanitizationStrategy,
)
from key_value.aio.wrappers.encryption import (  # noqa: E402
    FernetEncryptionWrapper,
)
from mcp.types import ToolAnnotations  # noqa: E402
from starlette.responses import HTMLResponse, Response  # noqa: E402

DENIED = "tool not available"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
QUERY_VALUE_RE = re.compile(r"([?&][^=&\s'\"<>]+?=)[^&\s'\"<>)\]]+")
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")
MIN_TOKEN_LENGTH = 32
EXPIRY_WARNING_DAYS = 14

TOP_KEYS = {"hub", "upstreams", "groups", "agents"}
HUB_KEYS = {
    "name", "host", "port", "path", "state_dir", "audit_log",
    "audit_max_bytes", "audit_backups", "oauth_key", "oauth_dir", "status",
}
STATUS_KEYS = {"user", "password"}
UPSTREAM_KEYS = {"url", "headers", "auth", "callback_port", "scopes"}
GROUP_KEYS = {"allow", "groups", "access"}
AGENT_KEYS = {"token_sha256", "groups", "allow", "expires", "read_only"}

log = logging.getLogger("agent-hub")


class SecretRedactor:
    """Scrub resolved secrets and URL query values from every log record."""

    def __init__(self):
        self._secrets: list[str] = []
        self._installed = False

    def add(self, secret: str) -> None:
        if len(secret) < 4:
            return
        candidates = {secret, quote(secret, safe="")}
        changed = False
        for item in candidates:
            if item and item not in self._secrets:
                self._secrets.append(item)
                changed = True
        if changed:
            self._secrets.sort(key=len, reverse=True)

    def scrub(self, text: str) -> str:
        for secret in self._secrets:
            if secret in text:
                text = text.replace(secret, "<REDACTED>")
        text = QUERY_VALUE_RE.sub(r"\1<REDACTED>", text)
        return BEARER_RE.sub("Bearer <REDACTED>", text)

    def _scrub_args(self, args):
        if isinstance(args, tuple):
            return tuple(
                self.scrub(a) if isinstance(a, str) else a for a in args)
        if isinstance(args, dict):
            return {
                k: self.scrub(v) if isinstance(v, str) else v
                for k, v in args.items()
            }
        return args

    def scrub_record(self, record) -> None:
        """Scrub one log record in place.

        Some formatters unpack record.args (uvicorn's access log expects a
        5-tuple), so msg and args stay as they are when nothing needs
        removing, and are rewritten value by value when that suffices.
        Only when a secret cannot be removed that way does the record
        collapse to a preformatted message with no args.
        """
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        clean = self.scrub(msg)
        if clean != msg:
            template = record.msg
            if isinstance(template, str):
                template = self.scrub(template)
            args = self._scrub_args(record.args)
            try:
                rebuilt = template % args if args else template
            except Exception:
                rebuilt = None
            if rebuilt == clean:
                record.msg, record.args = template, args
            else:
                record.msg, record.args = clean, ()
        if record.exc_info and record.exc_info != (None, None, None):
            tb = "".join(traceback.format_exception(*record.exc_info))
            record.msg = f"{clean}\n{self.scrub(tb).rstrip()}"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
        elif record.exc_text:
            record.exc_text = self.scrub(record.exc_text)
        if record.stack_info:
            record.stack_info = self.scrub(record.stack_info)

    def install(self) -> None:
        if self._installed:
            return
        orig_factory = logging.getLogRecordFactory()
        redactor = self

        def factory(*args, **kwargs):
            record = orig_factory(*args, **kwargs)
            redactor.scrub_record(record)
            return record

        logging.setLogRecordFactory(factory)
        self._installed = True


REDACTOR = SecretRedactor()


# -- Configuration ----------------------------------------------------------


def default_config_path():
    env = os.environ.get("AGENT_HUB_CONFIG")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "agent-hub" / "hub.toml"


def default_state_dir():
    base = os.environ.get("XDG_STATE_HOME") or "~/.local/state"
    return Path(base).expanduser() / "agent-hub"


def _resolve_path(value, base):
    path = Path(value).expanduser()
    return path if path.is_absolute() else Path(base) / path


def resolve_paths(config, base):
    """Fill [hub] defaults and make its paths absolute.

    Relative paths are relative to BASE, the config file's directory. The
    state directory holds the OAuth store and the pid file; the audit log
    defaults to it too.
    """
    hub = config.setdefault("hub", {})
    if not isinstance(hub, dict):
        raise ValueError("[hub] must be a table")
    for key in ("state_dir", "audit_log", "oauth_dir"):
        if key in hub and not isinstance(hub[key], str):
            raise ValueError(f"[hub] {key} must be a string")
    hub.setdefault("name", "agent-hub")
    hub.setdefault("host", "127.0.0.1")
    hub.setdefault("port", 18797)
    hub.setdefault("path", "/mcp")
    state = hub.get("state_dir")
    state = _resolve_path(state, base) if state else default_state_dir()
    hub["state_dir"] = str(state)
    hub["audit_log"] = str(
        _resolve_path(hub.get("audit_log", state / "audit.jsonl"), base))
    hub["oauth_dir"] = str(
        _resolve_path(hub.get("oauth_dir", state / "oauth"), base))
    return config


def load_config(path):
    path = Path(path).expanduser()
    with path.open("rb") as f:
        config = tomllib.load(f)
    return resolve_paths(config, path.resolve().parent)


_SECRETS: dict[str, str] = {}


def env_secret(name):
    """Read a secret from the environment and remove it from os.environ.

    The value is kept in this process, so a variable referenced in several
    places (two upstreams sharing a key) resolves every time.
    """
    if name in _SECRETS:
        return _SECRETS[name]
    resolved = os.environ.pop(name, None)
    if not resolved:
        sys.exit(f"agent-hub: required env var {name} is unset")
    REDACTOR.add(resolved)
    _SECRETS[name] = resolved
    return resolved


def resolve_value(value):
    """Expand a configured value.

    `env:NAME` is the whole value from the environment; `${NAME}` inside a
    string (a URL with a token in its query, `Bearer ${NAME}`) is replaced.
    """
    if value.startswith("env:"):
        return env_secret(value[4:])
    return re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: env_secret(m[1]), value)


def expand_groups(groups_cfg, names, *, _stack=()):
    """Expand named exact-tool groups with cycle detection."""
    tools: set[str] = set()
    for name in names:
        if name in _stack:
            raise ValueError(f"group cycle involving {name!r}")
        if name not in groups_cfg:
            raise ValueError(f"unknown group {name!r}")
        spec = groups_cfg[name]
        tools.update(spec.get("allow", []))
        nested = spec.get("groups", [])
        if nested:
            tools.update(
                expand_groups(groups_cfg, nested, _stack=(*_stack, name))
            )
    return tools


def read_tools(config):
    """Tools the config classifies as read-only (groups with access=read)."""
    groups = config.get("groups", {})
    names = [g for g, spec in groups.items() if spec.get("access") == "read"]
    return expand_groups(groups, names)


def agent_allow(config, agent_spec):
    """Effective exact-tool allowlist for one agent (groups + allow).

    A read-only agent never gets more than the read-classified tools, even
    if validation were bypassed.
    """
    groups = config.get("groups", {})
    tools = (
        expand_groups(groups, agent_spec.get("groups", []))
        | set(agent_spec.get("allow", []))
    )
    if agent_spec.get("read_only"):
        tools &= read_tools(config)
    return tools


def token_hashes(spec):
    value = spec.get("token_sha256", [])
    return [value] if isinstance(value, str) else list(value)


def expiry_timestamp(value):
    """Epoch seconds at which a token stops working, or None.

    A TOML date means the start of that day in the hub's local time; a
    datetime without an offset is local time too.
    """
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value.timestamp()
    if isinstance(value, dt.date):
        return dt.datetime.combine(value, dt.time.min).timestamp()
    raise ValueError(f"not a TOML date or datetime: {value!r}")


def _check_keys(owner, spec, allowed):
    if not isinstance(spec, dict):
        raise ValueError(f"{owner} must be a table")
    unknown = sorted(set(spec) - allowed)
    if unknown:
        raise ValueError(f"{owner} has unknown keys: {', '.join(unknown)}")


def _check_tool_names(owner, tools, upstreams):
    for tool in tools:
        if "_" not in tool:
            raise ValueError(
                f"{owner} allow entry {tool!r} must be prefixed with "
                "'<upstream>_'"
            )
        upstream = tool.split("_", 1)[0]
        if upstream not in upstreams:
            raise ValueError(
                f"{owner} allows {tool!r}, but upstream {upstream!r} "
                "is not configured"
            )


def _validate_upstreams(config):
    upstreams = config.get("upstreams", {})
    for name, spec in upstreams.items():
        owner = f"upstream {name!r}"
        if "_" in name:
            raise ValueError(f"upstream name {name!r} must not contain '_'")
        _check_keys(owner, spec, UPSTREAM_KEYS)
        if not isinstance(spec.get("url"), str):
            raise ValueError(f"{owner} needs a url")
        headers = spec.get("headers", {})
        if not isinstance(headers, dict) or not all(
            isinstance(v, str) for v in headers.values()
        ):
            raise ValueError(f"{owner} headers must be a table of strings")
        auth = spec.get("auth")
        if auth not in (None, "oauth"):
            raise ValueError(f"{owner} auth must be \"oauth\" or absent")
        if auth == "oauth":
            if not isinstance(spec.get("callback_port"), int):
                raise ValueError(f"{owner} needs an integer callback_port")
            if "oauth_key" not in config.get("hub", {}):
                raise ValueError(
                    f"{owner} uses OAuth, so [hub] needs oauth_key")


def _validate_groups(config):
    groups = config.get("groups", {})
    upstreams = config.get("upstreams", {})
    for gname, spec in groups.items():
        owner = f"group {gname!r}"
        _check_keys(owner, spec, GROUP_KEYS)
        access = spec.get("access")
        if access not in (None, "read"):
            raise ValueError(f"{owner} access must be \"read\" or absent")
        _check_tool_names(owner, expand_groups(groups, [gname]), upstreams)
        if access == "read":
            for nested in spec.get("groups", []):
                if groups.get(nested, {}).get("access") != "read":
                    raise ValueError(
                        f"read group {gname!r} includes {nested!r}, which "
                        "is not a read group"
                    )


def _validate_agents(config):
    agents = config.get("agents", {})
    upstreams = config.get("upstreams", {})
    reads = read_tools(config)
    seen_hashes: dict[str, str] = {}
    for agent, spec in agents.items():
        owner = f"agent {agent!r}"
        _check_keys(owner, spec, AGENT_KEYS)
        hashes = token_hashes(spec)
        if not hashes:
            raise ValueError(f"{owner} needs token_sha256")
        for digest in hashes:
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                raise ValueError(
                    f"{owner} token_sha256 must be 64 lowercase hex "
                    "characters"
                )
            if digest in seen_hashes:
                raise ValueError(
                    f"agents {seen_hashes[digest]!r} and {agent!r} share "
                    "the same token_sha256"
                )
            seen_hashes[digest] = agent
        try:
            expiry_timestamp(spec.get("expires"))
        except ValueError as exc:
            raise ValueError(
                f"{owner} expires must be a TOML date such as "
                "2027-01-31, not a string"
            ) from exc
        if not isinstance(spec.get("read_only", False), bool):
            raise ValueError(f"{owner} read_only must be true or false")
        groups = config.get("groups", {})
        tools = (
            expand_groups(groups, spec.get("groups", []))
            | set(spec.get("allow", []))
        )
        _check_tool_names(owner, tools, upstreams)
        if spec.get("read_only"):
            extra = sorted(tools - reads)
            if extra:
                raise ValueError(
                    f"read-only {owner} allows tools outside every read "
                    f"group: {', '.join(extra)}"
                )


def _check_string_list(owner, key, value):
    if not isinstance(value, list) or not all(
        isinstance(v, str) for v in value
    ):
        raise ValueError(f"{owner} {key} must be a list of strings")


def _validate_shapes(config):
    """Presence and types, so later code never meets a surprise."""
    _check_keys("config", config, TOP_KEYS)
    for section in ("upstreams", "groups", "agents"):
        value = config.setdefault(section, {})
        if not isinstance(value, dict):
            raise ValueError(f"[{section}] must be a table")
    if not config["upstreams"]:
        raise ValueError("config needs at least one [upstreams.NAME]")
    hub = config.get("hub", {})
    _check_keys("[hub]", hub, HUB_KEYS)
    for key in ("name", "host", "path", "audit_log", "state_dir",
                "oauth_dir", "oauth_key"):
        if key in hub and not isinstance(hub[key], str):
            raise ValueError(f"[hub] {key} must be a string")
    for key in ("port", "audit_max_bytes", "audit_backups"):
        if key in hub and (
            not isinstance(hub[key], int) or isinstance(hub[key], bool)
        ):
            raise ValueError(f"[hub] {key} must be an integer")
    if "port" in hub and not 0 < hub["port"] < 65536:
        raise ValueError("[hub] port must be between 1 and 65535")
    if "path" in hub and not hub["path"].startswith("/"):
        raise ValueError("[hub] path must start with /")
    if "status" in hub:
        status = hub["status"]
        _check_keys("[hub.status]", status, STATUS_KEYS)
        if not isinstance(status.get("password"), str):
            raise ValueError("[hub.status] needs a password")
        if not isinstance(status.get("user", ""), str):
            raise ValueError("[hub.status] user must be a string")
    for kind in ("groups", "agents"):
        for name, spec in config[kind].items():
            owner = f"{kind[:-1]} {name!r}"
            if not isinstance(spec, dict):
                raise ValueError(f"{owner} must be a table")
            for key in ("allow", "groups"):
                if key in spec:
                    _check_string_list(owner, key, spec[key])
            if kind == "agents" and "token_sha256" in spec:
                value = spec["token_sha256"]
                if not isinstance(value, str):
                    _check_string_list(owner, "token_sha256", value)


def secret_literals(config):
    """Secret-bearing settings written as literals instead of env refs."""
    def literal(value):
        return isinstance(value, str) and not (
            value.startswith("env:") or "${" in value)

    found = []
    hub = config.get("hub", {})
    if literal(hub.get("oauth_key")):
        found.append("[hub] oauth_key")
    if literal(hub.get("status", {}).get("password")):
        found.append("[hub.status] password")
    for name, spec in config.get("upstreams", {}).items():
        for header, value in spec.get("headers", {}).items():
            if literal(value):
                found.append(f"upstream {name!r} header {header}")
        url = spec.get("url", "")
        if urlsplit(url).query and literal(url):
            found.append(f"upstream {name!r} url query")
    return found


def validate_config(config):
    """Validate the whole config; raise ValueError on the first problem."""
    _validate_shapes(config)
    _validate_upstreams(config)
    _validate_groups(config)
    _validate_agents(config)


def is_loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# -- Audit and health -------------------------------------------------------


class Audit:
    def __init__(self, path, *, max_recent=100, max_bytes=10 * 1024 * 1024,
                 backups=5):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._max_bytes = max_bytes
        self._backups = backups
        self._recent: collections.deque[dict] = collections.deque(
            maxlen=max_recent
        )
        self._seed_recent()

    def _seed_recent(self):
        if not self.path.exists():
            return
        with self.path.open() as f:
            lines = collections.deque(f, maxlen=self._recent.maxlen)
        for line in lines:
            try:
                self._recent.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    def _rotate_locked(self):
        if self._max_bytes <= 0 or not self.path.exists():
            return
        if self.path.stat().st_size < self._max_bytes:
            return
        for i in range(self._backups, 0, -1):
            src = self.path if i == 1 else Path(f"{self.path}.{i - 1}")
            dst = Path(f"{self.path}.{i}")
            if src.exists():
                os.replace(src, dst)

    def write(self, **fields):
        fields["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        line = json.dumps(fields, sort_keys=True) + "\n"
        with self._lock:
            self._rotate_locked()
            with self.path.open("a") as f:
                f.write(line)
            self._recent.append(dict(fields))

    def tail(self, n):
        with self._lock:
            items = list(self._recent)
        return list(reversed(items[-n:]))


class HubTokens(TokenVerifier):
    """Map a bearer token to an agent name by SHA-256 hash.

    An agent may list several hashes (to rotate without downtime) and an
    `expires` date after which none of them work.
    """

    def __init__(self, agents, audit=None, *, clock=time.time):
        super().__init__()
        self.audit = audit
        self.clock = clock
        self.by_hash: dict[str, str] = {}
        self.expires: dict[str, float | None] = {}
        self._expired_logged: dict[str, float] = {}
        self.update(agents)

    def update(self, agents):
        self.by_hash = {
            digest: name
            for name, spec in agents.items()
            for digest in token_hashes(spec)
        }
        self.expires = {
            name: expiry_timestamp(spec.get("expires"))
            for name, spec in agents.items()
        }

    def _note_expired(self, agent, now):
        # One audit line per agent per minute, not one per request.
        if self.audit is None:
            return
        if now - self._expired_logged.get(agent, 0) < 60:
            return
        self._expired_logged[agent] = now
        self.audit.write(
            agent=agent, method="auth", decision="deny", error="TokenExpired")

    async def verify_token(self, token):
        digest = hashlib.sha256(token.encode()).hexdigest()
        agent = None
        for known, name in self.by_hash.items():
            if hmac.compare_digest(digest, known):
                agent = name
        if agent is None:
            return None
        now = self.clock()
        expires = self.expires.get(agent)
        if expires is not None and now >= expires:
            self._note_expired(agent, now)
            return None
        return AccessToken(
            token="hub",
            client_id=agent,
            scopes=[],
            expires_at=int(expires) if expires is not None else None,
        )


class Health:
    """Last success and last error per upstream, for the status page."""

    def __init__(self, names):
        self.state = {n: {"ok": None, "error": None} for n in names}

    def record_upstream(self, upstream, error):
        if upstream not in self.state:
            return
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        if error:
            self.state[upstream]["error"] = f"{stamp} {error}"
        else:
            self.state[upstream]["ok"] = stamp

    def record(self, tool, error):
        self.record_upstream(tool.split("_", 1)[0], error)


# -- Policy -----------------------------------------------------------------


class Policy(Middleware):
    """Deny by default. Exact tool names only.

    The hub's own read/write classification replaces whatever readOnlyHint
    an upstream claims: a tool is advertised as read-only only if a group
    with access = "read" contains it.
    """

    def __init__(self, allow_map, reads, audit, health):
        self.allow = {n: set(tools) for n, tools in allow_map.items()}
        self.reads = set(reads)
        self.audit = audit
        self.health = health

    def update(self, allow_map, reads):
        self.allow = {n: set(tools) for n, tools in allow_map.items()}
        self.reads = set(reads)

    def agent(self):
        token = get_access_token()
        return token.client_id if token else None

    def allowed(self, agent, tool):
        return agent is not None and tool in self.allow.get(agent, set())

    def annotate(self, tool):
        """Replace the upstream's safety hints with the hub's own.

        A tool in a read group is read-only. Any other tool gets the MCP
        defaults for an unvouched tool: not read-only, destructive, not
        idempotent. The title and openWorldHint pass through.
        """
        if tool.name in self.reads:
            hints = {"read_only_hint": True}
        else:
            hints = {
                "read_only_hint": False,
                "destructive_hint": True,
                "idempotent_hint": False,
            }
        # These are MCP SDK v2 field names; readOnlyHint and friends are
        # only wire aliases, and model_copy(update=...) silently ignores
        # an alias.
        current = tool.annotations
        if current is None:
            annotations = ToolAnnotations(**hints)
        else:
            annotations = current.model_copy(update=hints)
        return tool.model_copy(update={"annotations": annotations})

    async def on_list_tools(self, context, call_next):
        agent = self.agent()
        tools = await call_next(context)
        visible = [
            self.annotate(t) for t in tools if self.allowed(agent, t.name)
        ]
        self.audit.write(
            agent=agent, method="tools/list", decision="allow",
            visible=len(visible), total=len(tools),
        )
        return visible

    async def on_call_tool(self, context, call_next):
        agent = self.agent()
        tool = context.message.name
        if not self.allowed(agent, tool):
            self.audit.write(
                agent=agent, method="tools/call", tool=tool, decision="deny",
            )
            raise ToolError(DENIED)
        start = time.monotonic()
        error = None
        try:
            result = await call_next(context)
            if getattr(result, "is_error", False):
                error = "ToolResultError"
            return result
        except Exception as exc:
            error = type(exc).__name__
            raise
        finally:
            self.health.record(tool, error)
            self.audit.write(
                agent=agent, method="tools/call", tool=tool,
                decision="allow", error=error,
                ms=round((time.monotonic() - start) * 1000),
            )

    # Resources and prompts are off: list nothing, read nothing.
    async def on_list_resources(self, context, call_next):
        return []

    async def on_list_resource_templates(self, context, call_next):
        return []

    async def on_list_prompts(self, context, call_next):
        return []

    async def on_read_resource(self, context, call_next):
        raise ToolError(DENIED)

    async def on_get_prompt(self, context, call_next):
        raise ToolError(DENIED)


# -- Upstreams --------------------------------------------------------------


class HubOAuth(OAuth):
    """OAuth that never opens a browser from the running hub.

    A missing or revoked grant makes that one upstream fail with a clear
    message. Sign-in happens only through `hub.py authorize`.
    """

    upstream_name = "<upstream>"

    async def redirect_handler(self, authorization_url):
        raise RuntimeError(
            f"upstream needs sign-in: run `hub.py authorize "
            f"{self.upstream_name}` on the hub's host"
        )


def token_store(config):
    hub = config["hub"]
    key = resolve_value(hub["oauth_key"])
    directory = Path(hub["oauth_dir"])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Keys are upstream URLs; without sanitization their slashes become
    # nonexistent subdirectories and every write fails.
    store = FileTreeStore(
        data_directory=directory,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(
            directory),
        collection_sanitization_strategy=(
            FileTreeV1CollectionSanitizationStrategy(directory)),
    )
    return FernetEncryptionWrapper(store, fernet=Fernet(key.encode()))


def oauth_for(name, spec, store, client_name, interactive):
    if interactive:
        auth = OAuth(
            client_name=client_name,
            token_storage=store,
            callback_port=spec["callback_port"],
            scopes=spec.get("scopes"),
        )
    else:
        auth = HubOAuth(
            client_name=client_name,
            token_storage=store,
            callback_port=spec["callback_port"],
            scopes=spec.get("scopes"),
        )
        auth.upstream_name = name
    return auth


class SharedClient:
    """One long-lived upstream session, reconnected on demand.

    Used for OAuth upstreams so that concurrent requests never race on a
    refresh-token rotation.
    """

    def __init__(self, make_client):
        self.make_client = make_client
        self.client = None
        self.lock = asyncio.Lock()

    async def _close_locked(self):
        if self.client is not None:
            old, self.client = self.client, None
            try:
                await old.close()
            except Exception:
                pass

    async def __call__(self):
        async with self.lock:
            if self.client is None or not self.client.is_connected():
                await self._close_locked()
                client = self.make_client()
                await client.__aenter__()
                self.client = client
            return self.client

    async def reset(self):
        async with self.lock:
            await self._close_locked()


class UpstreamGate(Middleware):
    """Per-upstream: skip unallowed agents, track health, reset OAuth."""

    def __init__(self, name, allowed_agents, health, shared_client=None):
        self.name = name
        self.allowed_agents = allowed_agents
        self.health = health
        self.shared_client = shared_client

    async def on_list_tools(self, context, call_next):
        token = get_access_token()
        agent = token.client_id if token else None
        if agent not in self.allowed_agents:
            return []
        try:
            tools = await call_next(context)
        except Exception as exc:
            if self.shared_client is None:
                self.health.record_upstream(self.name, type(exc).__name__)
                raise
            # A long-lived OAuth session can go stale when the access token
            # expires; the first list after that fails and the upstream
            # vanished from tools/list. Listing is idempotent: reconnect
            # (which refreshes the token) and retry once.
            await self.shared_client.reset()
            try:
                tools = await call_next(context)
            except Exception as exc2:
                self.health.record_upstream(self.name, type(exc2).__name__)
                await self.shared_client.reset()
                raise
        self.health.record_upstream(self.name, None)
        return tools

    async def on_call_tool(self, context, call_next):
        try:
            return await call_next(context)
        except ValidationError:
            raise
        except Exception:
            # An upstream's own tool errors come back as results, not
            # exceptions, so this is a transport or local failure. Starting
            # a fresh session is the cheap recovery; calls in flight on the
            # old one fail and the agent retries.
            if self.shared_client is not None:
                await self.shared_client.reset()
            raise


def upstream_proxy(name, spec, store, client_name="agent-hub"):
    headers = {k: resolve_value(v) for k, v in spec.get("headers", {}).items()}
    url = resolve_value(spec["url"])
    if spec.get("auth") == "oauth":
        auth = oauth_for(name, spec, store, client_name, interactive=False)

        def make_client():
            transport = StreamableHttpTransport(
                url, headers=headers or None, auth=auth
            )
            return Client(transport)

        shared = SharedClient(make_client)
        proxy = FastMCPProxy(
            client_factory=shared,
            name=name,
            mask_error_details=True,
            provider_error_strategy="raise",
        )
        return proxy, shared
    transport = StreamableHttpTransport(url, headers=headers)
    # Never forward the agent's Authorization (its hub token) upstream, and
    # disable upstream-initiated roots, sampling, and elicitation callbacks.
    client = ProxyClient(
        transport,
        forward_incoming_headers=False,
        roots=None,
        sampling_handler=None,
        elicitation_handler=None,
    )
    proxy = create_proxy(
        client,
        name=name,
        mask_error_details=True,
        provider_error_strategy="raise",
    )
    return proxy, None


# -- Status page ------------------------------------------------------------


def status_route(hub, config, audit, health):
    status = config["hub"].get("status", {})
    password = resolve_value(status["password"]) if status else None
    expected_user = status.get("user", "admin")

    def authorized(request):
        if password is None:
            return False
        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(header[6:]).decode()
        except Exception:
            return False
        user, _, given = raw.partition(":")
        user_ok = hmac.compare_digest(user.encode(), expected_user.encode())
        pass_ok = hmac.compare_digest(given.encode(), password.encode())
        return user_ok and pass_ok

    @hub.custom_route("/status", methods=["GET"])
    async def page(request):
        if not password or not authorized(request):
            return Response(
                "authentication required", status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="agent-hub"'},
            )
        return HTMLResponse(render_status(config, audit, health))


def _expiry_label(spec, now=None):
    expires = expiry_timestamp(spec.get("expires"))
    if expires is None:
        return "never"
    now = time.time() if now is None else now
    label = str(spec["expires"])
    if now >= expires:
        return f"{label} (expired)"
    if expires - now < EXPIRY_WARNING_DAYS * 86400:
        return f"{label} (soon)"
    return label


def render_status(config, audit, health):
    e = html.escape
    reads = read_tools(config)
    rows = []
    for name, spec in config["upstreams"].items():
        state = health.state.get(name, {})
        rows.append(
            f"<tr><td>{e(name)}</td><td>{e(spec.get('auth', 'header'))}</td>"
            f"<td>{e(state.get('ok') or '-')}</td>"
            f"<td>{e(state.get('error') or '-')}</td></tr>"
        )
    agents = []
    for name, spec in config["agents"].items():
        tools = ", ".join(
            e(t) + ("" if t in reads else " (w)")
            for t in sorted(agent_allow(config, spec))
        )
        groups = spec.get("groups", [])
        label = e(name)
        if groups:
            label += f"<br><small>({e(', '.join(groups))})</small>"
        mode = "read-only" if spec.get("read_only") else "-"
        agents.append(
            f"<tr><td>{label}</td><td>{e(_expiry_label(spec))}</td>"
            f"<td>{mode}</td><td>{tools}</td></tr>"
        )
    events = []
    for ev in audit.tail(100):
        events.append(
            f"<tr><td>{e(ev.get('ts', ''))}</td>"
            f"<td>{e(str(ev.get('agent')))}</td>"
            f"<td>{e(ev.get('method', ''))}</td>"
            f"<td>{e(ev.get('tool', ''))}</td>"
            f"<td>{e(ev.get('decision', ''))}</td>"
            f"<td>{e(str(ev.get('error') or ''))}</td>"
            f"<td>{e(str(ev.get('ms', '')))}</td></tr>"
        )
    title = e(config["hub"].get("name", "agent-hub"))
    return f"""<!doctype html><meta charset="utf-8">
<title>{title}</title>
<style>
body{{font:14px/1.4 ui-monospace,monospace;margin:1.5rem;max-width:80rem}}
table{{border-collapse:collapse;margin-bottom:2rem}}
td,th{{border-bottom:1px solid #ccc;padding:.25rem .75rem;text-align:left;
vertical-align:top}}
</style>
<h1>{title}</h1>
<p>Read-only. Policy lives in the hub's config file. Upstream health covers
this process since it started. (w) marks a tool outside every read group.</p>
<h2>Upstreams</h2>
<table><tr><th>name</th><th>auth</th><th>last ok</th><th>last error</th></tr>
{''.join(rows)}</table>
<h2>Agents</h2>
<table><tr><th>agent</th><th>expires</th><th>mode</th><th>allowed tools</th>
</tr>{''.join(agents)}</table>
<h2>Last 100 events</h2>
<table><tr><th>time</th><th>agent</th><th>method</th><th>tool</th>
<th>decision</th><th>error</th><th>ms</th></tr>{''.join(events)}</table>
"""


# -- Assembly ---------------------------------------------------------------


def _allowed_agents_by_upstream(upstreams, allow_map):
    result = {}
    for name in upstreams:
        prefix = f"{name}_"
        result[name] = {
            agent
            for agent, tools in allow_map.items()
            if any(t.startswith(prefix) for t in tools)
        }
    return result


def build(config, *, config_path=None):
    REDACTOR.install()
    resolve_paths(config, Path.cwd())
    validate_config(config)
    hub_cfg = config["hub"]
    audit = Audit(
        hub_cfg["audit_log"],
        max_bytes=hub_cfg.get("audit_max_bytes", 10 * 1024 * 1024),
        backups=hub_cfg.get("audit_backups", 5),
    )
    health = Health(config["upstreams"])
    agents = config.get("agents", {})
    allow_map = {a: agent_allow(config, s) for a, s in agents.items()}
    needs_store = any(
        s.get("auth") == "oauth" for s in config["upstreams"].values())
    store = token_store(config) if needs_store else None
    tokens = HubTokens(agents, audit)
    policy = Policy(allow_map, read_tools(config), audit, health)
    shared_clients: list[SharedClient] = []
    gates: dict[str, UpstreamGate] = {}

    def reload_policy():
        if not config_path:
            return False
        try:
            new_cfg = load_config(config_path)
            validate_config(new_cfg)
        except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
            log.error("policy reload failed (keeping current policy): %s", exc)
            audit.write(
                agent="hub", method="policy/reload", decision="deny",
                error=type(exc).__name__,
            )
            return False
        for section in ("hub", "upstreams"):
            if new_cfg.get(section) != config.get(section):
                log.warning(
                    "policy reload: [%s] changed; restart the hub to apply "
                    "it", section,
                )
        new_agents = new_cfg.get("agents", {})
        new_allow = {a: agent_allow(new_cfg, s) for a, s in new_agents.items()}
        tokens.update(new_agents)
        policy.update(new_allow, read_tools(new_cfg))
        by_up = _allowed_agents_by_upstream(gates, new_allow)
        for name, gate in gates.items():
            gate.allowed_agents = by_up[name]
        config["agents"] = new_agents
        config["groups"] = new_cfg.get("groups", {})
        audit.write(
            agent="hub", method="policy/reload", decision="allow",
            agents=len(new_agents),
        )
        log.info(
            "reloaded policy from %s (%d agents)", config_path, len(new_agents))
        return True

    @asynccontextmanager
    async def lifespan(_app):
        loop = asyncio.get_running_loop()
        sighup_installed = False
        if config_path and hasattr(signal, "SIGHUP"):
            # Signal handlers need the main thread of a Unix event loop;
            # anywhere else (tests, embedding) reload is just unavailable.
            try:
                loop.add_signal_handler(signal.SIGHUP, reload_policy)
                sighup_installed = True
            except (NotImplementedError, RuntimeError, ValueError):
                log.warning("SIGHUP reload unavailable in this process")
        try:
            yield
        finally:
            if sighup_installed:
                loop.remove_signal_handler(signal.SIGHUP)
            for sc in shared_clients:
                await sc.reset()

    hub = FastMCP(
        hub_cfg["name"],
        auth=tokens,
        mask_error_details=True,
        lifespan=lifespan,
    )
    by_up = _allowed_agents_by_upstream(config["upstreams"], allow_map)
    for name, spec in config["upstreams"].items():
        proxy, shared = upstream_proxy(name, spec, store, hub_cfg["name"])
        if shared is not None:
            shared_clients.append(shared)
        gate = UpstreamGate(name, by_up[name], health, shared)
        gates[name] = gate
        proxy.add_middleware(gate)
        hub.mount(proxy, namespace=name)
    hub.add_middleware(policy)
    status_route(hub, config, audit, health)
    hub.reload_policy = reload_policy
    return hub


# -- Commands ---------------------------------------------------------------


def _pid_file(config):
    return Path(config["hub"]["state_dir"]) / "hub.pid"


def _claim_pid_file(config):
    """Write our pid and hold an exclusive lock on the file while we run.

    The lock is what `reload` trusts: a pid file nobody holds locked is
    stale, whatever pid it names. It also stops a second hub from starting
    on the same state directory.
    """
    path = _pid_file(config)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        sys.exit(f"agent-hub: another hub holds {path}")
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode())
    return path, fd


def _locked_pid(path):
    """The pid in PATH if a running process holds its lock, else None."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            text = os.pread(fd, 32, 0).decode().strip()
            return int(text) if text.isdigit() else None
        fcntl.flock(fd, fcntl.LOCK_UN)
        return None
    finally:
        os.close(fd)


def serve(config, config_path):
    try:
        hub = build(config, config_path=config_path)
    except ValueError as exc:
        sys.exit(f"agent-hub: {exc}")
    h = config["hub"]
    if not is_loopback(h["host"]):
        log.warning(
            "serving plain HTTP on %s; hub tokens cross the network in "
            "clear text unless TLS terminates in front of the hub", h["host"],
        )
    pid_file, pid_fd = _claim_pid_file(config)
    try:
        hub.run(
            transport="http", host=h["host"], port=h["port"], path=h["path"],
            show_banner=False,
        )
    finally:
        try:
            pid_file.unlink()
        except OSError:
            pass
        os.close(pid_fd)


def check(config, *, now=None):
    try:
        validate_config(config)
    except ValueError as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 1
    status = 0
    for name, spec in config.get("agents", {}).items():
        label = _expiry_label(spec, now)
        tools = agent_allow(config, spec)
        mode = " read-only" if spec.get("read_only") else ""
        print(f"{name}: {len(tools)} tools{mode}, expires {label}")
        if "(expired)" in label:
            status = 1
    for where in secret_literals(config):
        print(f"warning: {where} is a literal; use env:NAME or ${{NAME}}",
              file=sys.stderr)
    print(f"ok: {len(config.get('agents', {}))} agents, "
          f"{len(config.get('upstreams', {}))} upstreams")
    return status


def reload_running(config, *, timeout=5.0):
    pid_file = _pid_file(config)
    pid = _locked_pid(pid_file)
    if pid is None:
        print(f"reload: no running hub holds {pid_file}", file=sys.stderr)
        return 1
    command = subprocess.run(
        ["ps", "-p", str(pid), "-o", "command="],
        capture_output=True, text=True, check=False,
    ).stdout
    if "hub.py" not in command or "serve" not in command:
        print(f"reload: pid {pid} is not a running hub", file=sys.stderr)
        return 1
    audit_path = Path(config["hub"]["audit_log"])
    offset = audit_path.stat().st_size if audit_path.exists() else 0
    os.kill(pid, signal.SIGHUP)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(0.2)
        if not audit_path.exists():
            continue
        size = audit_path.stat().st_size
        with audit_path.open() as f:
            f.seek(offset if size >= offset else 0)
            for line in f:
                if '"policy/reload"' not in line:
                    continue
                print(f"reload: pid {pid}: {line.strip()}")
                return 0 if '"decision": "allow"' in line else 1
    print("reload: no policy/reload line in the audit log", file=sys.stderr)
    return 1


async def authorize(config, name):
    spec = config["upstreams"].get(name)
    if spec is None or spec.get("auth") != "oauth":
        sys.exit(f"agent-hub: upstream {name!r} is not an OAuth upstream")
    hub = config["hub"]
    auth = oauth_for(
        name, spec, token_store(config), hub["name"], interactive=True)
    url = resolve_value(spec["url"])
    transport = StreamableHttpTransport(url, auth=auth)
    async with Client(transport) as client:
        tools = await client.list_tools()
    print(f"{name}: signed in; {len(tools)} tools visible upstream")


async def list_upstream_tools(config, only=None):
    """Print every upstream tool with the upstream's own read-only claim.

    For writing groups: the claim is the upstream's word, not the hub's.
    """
    upstreams = config["upstreams"]
    if only is not None and only not in upstreams:
        sys.exit(f"agent-hub: no upstream {only!r}")
    selected = {
        n: s for n, s in upstreams.items() if only is None or n == only}
    store = None
    if any(s.get("auth") == "oauth" for s in selected.values()):
        store = token_store(config)
    claims = {True: "claims read-only", False: "claims writes", None: "-"}
    reads = read_tools(config)
    status = 0
    for name, spec in selected.items():
        proxy, shared = upstream_proxy(name, spec, store, config["hub"]["name"])
        try:
            async with Client(proxy) as client:
                tools = await client.list_tools()
        except Exception as exc:
            print(f"{name}: {type(exc).__name__}", file=sys.stderr)
            status = 1
            continue
        finally:
            if shared is not None:
                await shared.reset()
        for tool in sorted(tools, key=lambda t: t.name):
            full = f"{name}_{tool.name}"
            hint = tool.annotations.read_only_hint if tool.annotations else None
            hub_says = "read group" if full in reads else "-"
            print(f"{full}\t{claims[hint]}\t{hub_says}")
            if full in reads and hint is False:
                print(f"warning: {full} is in a read group but the upstream "
                      "says it writes", file=sys.stderr)
    return status


def hash_token(stream=None):
    stream = sys.stdin if stream is None else stream
    if stream.isatty():
        token = getpass.getpass("token: ")
    else:
        token = stream.read()
    token = token.rstrip("\r\n")
    if len(token) < MIN_TOKEN_LENGTH:
        print(
            f"hash-token: a token needs at least {MIN_TOKEN_LENGTH} "
            "characters", file=sys.stderr,
        )
        return 1
    print(hashlib.sha256(token.encode()).hexdigest())
    return 0


def bridge_url_ok(url, allow_remote=False):
    """Where the bridge may send its token.

    By default only to a hub on this machine. The URL lives in the
    client's config, which the client's agent can often edit, so a remote
    hub needs --allow-remote on the command line as well as https.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    if is_loopback(parts.hostname or ""):
        return True
    return allow_remote and parts.scheme == "https"


def bridge_token(args):
    if args.token_env:
        token = os.environ.pop(args.token_env, None)
        if not token:
            sys.exit(f"agent-hub bridge: {args.token_env} is unset")
        return token
    command = [
        "/usr/bin/security", "find-generic-password", "-s", args.keychain,
    ]
    if args.account:
        command += ["-a", args.account]
    command.append("-w")
    result = subprocess.run(
        command, capture_output=True, text=True, check=False)
    token = result.stdout.rstrip("\n")
    if result.returncode != 0 or not token:
        sys.exit(
            f"agent-hub bridge: no keychain item for service "
            f"{args.keychain!r}"
        )
    return token


def bridge(url, token):
    """Serve the hub over stdio for one agent, holding that agent's token.

    For clients that can start a local command but can only pass a hub
    token as a literal header in a config file.
    """
    REDACTOR.add(token)
    transport = StreamableHttpTransport(
        url, headers={"Authorization": f"Bearer {token}"})
    client = ProxyClient(
        transport,
        forward_incoming_headers=False,
        roots=None,
        sampling_handler=None,
        elicitation_handler=None,
    )
    proxy = create_proxy(client, name="agent-hub")
    proxy.run(transport="stdio", show_banner=False)


def _parser():
    parser = argparse.ArgumentParser(
        prog="hub.py",
        description="One MCP endpoint for several agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def with_config(p):
        p.add_argument(
            "--config", type=Path, default=None,
            help="config file (default: $AGENT_HUB_CONFIG or "
            "~/.config/agent-hub/hub.toml)",
        )
        return p

    with_config(sub.add_parser("serve", help="run the hub"))
    with_config(sub.add_parser("check", help="validate the config"))
    with_config(sub.add_parser("reload", help="reload agents and groups"))
    p = with_config(sub.add_parser("authorize", help="OAuth sign-in"))
    p.add_argument("upstream")
    p = with_config(sub.add_parser("tools", help="list upstream tools"))
    p.add_argument("upstream", nargs="?")
    sub.add_parser("hash-token", help="SHA-256 of a token on stdin")
    p = sub.add_parser("bridge", help="stdio bridge for one agent")
    p.add_argument("--url", required=True, help="the hub's MCP URL")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--token-env", metavar="NAME",
                        help="read the token from this variable")
    source.add_argument("--keychain", metavar="SERVICE",
                        help="read the token from the macOS keychain")
    p.add_argument("--account", help="keychain account name")
    p.add_argument("--allow-remote", action="store_true",
                   help="allow an https hub on another machine")
    return parser


def main(argv=None):
    REDACTOR.install()
    args = _parser().parse_args(argv)
    # httpx logs full request URLs at INFO; some upstream URLs carry keys.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    if args.command == "hash-token":
        return hash_token()
    if args.command == "bridge":
        if not bridge_url_ok(args.url, args.allow_remote):
            sys.exit(
                "agent-hub bridge: the hub must be on this machine, or "
                "use https and --allow-remote")
        bridge(args.url, bridge_token(args))
        return 0
    path = args.config or default_config_path()
    try:
        config = load_config(path)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        sys.exit(f"agent-hub: cannot read {path}: {exc}")
    if args.command == "check":
        return check(config)
    if args.command == "reload":
        return reload_running(config)
    if args.command in ("authorize", "tools"):
        try:
            validate_config(config)
        except ValueError as exc:
            sys.exit(f"agent-hub: {exc}")
        if args.command == "tools":
            return asyncio.run(list_upstream_tools(config, args.upstream))
        asyncio.run(authorize(config, args.upstream))
        return 0
    serve(config, path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
