"""What the shell scripts pass to the processes they start.

Stub `op` and `uv` executables on PATH stand in for the real ones: the
`op` stub loads the refs file verbatim and runs the command after `--`;
the `uv` stub records its environment.
"""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

OP_STUB = """#!/bin/sh
[ "$1" = run ] || exit 9
shift
f=
while [ $# -gt 0 ]; do
\tcase $1 in
\t--env-file) f=$2; shift 2 ;;
\t--) shift; break ;;
\t*) shift ;;
\tesac
done
if [ -n "$f" ]; then
\tset -a
\t. "$f"
\tset +a
fi
exec "$@"
"""

UV_STUB = """#!/bin/sh
env > "$ENV_OUT"
"""


@pytest.fixture
def stubs(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("op", OP_STUB), ("uv", UV_STUB)):
        path = bin_dir / name
        path.write_text(body)
        path.chmod(0o755)
    return bin_dir


def _names(env_text):
    return {
        line.split("=", 1)[0] for line in env_text.splitlines() if "=" in line
    }


def _base_env(tmp_path, stubs):
    return {
        "PATH": f"{stubs}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "ENV_OUT": str(tmp_path / "env.out"),
        "OP_SERVICE_ACCOUNT_TOKEN": "service-account-secret",
        "OP_CONNECT_TOKEN": "connect-secret",
    }


@pytest.mark.parametrize("command", ["serve", "check"])
def test_agent_hub_passes_no_op_variables(tmp_path, stubs, command):
    conf = tmp_path / "conf"
    conf.mkdir()
    (conf / "hub.toml").write_text("")
    (conf / "secrets.env.refs").write_text(
        "UPSTREAM_KEY=op://vault/item/credential\n")
    (conf / "op.env").write_text(
        "OP_SERVICE_ACCOUNT_TOKEN=from-op-env\nOP_CONNECT_HOST=connect\n")
    env = {**_base_env(tmp_path, stubs),
           "AGENT_HUB_CONFIG": str(conf / "hub.toml")}
    subprocess.run([str(ROOT / "agent-hub"), command], env=env, check=True,
                   timeout=30)
    names = _names((tmp_path / "env.out").read_text())
    assert not {n for n in names if n.startswith("OP_")}
    assert "AGENT_HUB_CONFIG" in names
    # Only `serve` (and `tools`) run under op with the refs file.
    assert ("UPSTREAM_KEY" in names) is (command == "serve")


def test_launch_keeps_only_tokens_named_in_refs(tmp_path, stubs):
    refs = tmp_path / "agent.env.refs"
    refs.write_text("AGENT_HUB_TOKEN_MINE=op://vault/mine/password\n")
    env = {
        **_base_env(tmp_path, stubs),
        "AGENT_HUB_TOKEN_OTHER": "someone-elses-token",
        "AGENT_HUB_OAUTH_KEY": "hub-secret",
        "GITHUB_TOKEN": "unrelated-secret",
    }
    out = subprocess.run(
        [str(ROOT / "clients" / "launch"), str(refs), "env"],
        env=env, check=True, capture_output=True, text=True, timeout=30,
    ).stdout
    names = _names(out)
    assert "AGENT_HUB_TOKEN_MINE" in names
    assert "AGENT_HUB_BEARER_MINE=Bearer op://vault/mine/password" in out
    for leaked in ("AGENT_HUB_TOKEN_OTHER", "AGENT_HUB_BEARER_OTHER",
                   "AGENT_HUB_OAUTH_KEY", "GITHUB_TOKEN",
                   "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "ENV_OUT"):
        assert leaked not in names
    assert names <= {
        "HOME", "PATH", "PWD", "SHLVL", "_", "OLDPWD",
        "AGENT_HUB_TOKEN_MINE", "AGENT_HUB_BEARER_MINE",
    }


def test_launch_refuses_refs_without_a_token(tmp_path, stubs):
    refs = tmp_path / "empty.env.refs"
    refs.write_text("SOMETHING_ELSE=op://vault/x/y\n")
    result = subprocess.run(
        [str(ROOT / "clients" / "launch"), str(refs), "env"],
        env=_base_env(tmp_path, stubs), capture_output=True, text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert "no AGENT_HUB_TOKEN_" in result.stderr


def test_scripts_are_executable():
    for name in ("agent-hub", "run-hub", "clients/launch"):
        assert os.access(ROOT / name, os.X_OK), name
