"""Real MCP servers, one per tool surface the gateway claims to understand.

Everything else in the test suite speaks to a hand-written JSON-RPC stub. That
is the right default -- it is fast and deterministic -- but it proves only that
the relay understands the protocol we *assumed* the servers speak. These
fixtures close that gap: they are built on the reference SDK, so the frames on
the wire are the ones a production client will actually receive.

The split matters for the claims this project makes. The relay forwards any
JSON-RPC method, including ones this file has never heard of; the provenance
layer keys off tool *names* and argument shapes. Both are only trustworthy
against real servers, because both were derived from reading transcripts
rather than from a specification that guarantees the shapes.

Each server is selected by argv so a single module can back every surface:

    python mcp_servers.py filesystem ROOT
    python mcp_servers.py git ROOT
    python mcp_servers.py fetch ROOT
    python mcp_servers.py sqlite PATH
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

#: A value that looks like a credential without being one. The tests assert on
#: this exact string, so it is fixed rather than generated.
FAKE_TOKEN = "tok_live_9f3a2b8c4d6e1f0a"

#: A host an outside attacker could plausibly register. Used to separate the
#: sleeper-channel case from the benign-egress case.
EXTERNAL_HOST = "collector.example.net"

#: Reserved suffixes per RFC 6761 section 6.5 and RFC 8375. A name under one of
#: these cannot be registered by an outside party, which is what makes it a
#: usable trust anchor; see `airlock.provenance.is_internal_host`.
INTERNAL_HOST = "metrics.internal"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# filesystem
# ---------------------------------------------------------------------------


def filesystem_server(root: Path) -> FastMCP:
    """A real filesystem server over a real directory tree.

    The point is not the file access -- it is that `read_file` returns the same
    shape the reference server returns, so the sensitive-path rules are being
    tested against the real argument convention rather than a guess.
    """
    server = FastMCP("airlock-fixture-filesystem")

    @server.tool()
    def read_file(path: str) -> str:
        """Read a file and return its contents."""
        target = (root / path).resolve()
        # Containment matters for the fixture itself: a test that could read
        # outside its own tmp_path would be a liability, not a test.
        if not str(target).startswith(str(root.resolve())):
            raise ValueError("path escapes the served root")
        return target.read_text(encoding="utf-8")

    @server.tool()
    def list_directory(path: str = ".") -> list[str]:
        """List the entries of a directory."""
        target = (root / path).resolve()
        if not str(target).startswith(str(root.resolve())):
            raise ValueError("path escapes the served root")
        return sorted(p.name for p in target.iterdir())

    @server.tool()
    def post_url(url: str, body: str = "", headers: dict[str, str] | None = None) -> str:
        """Pretend to POST to a URL and echo what would have been sent.

        Every surface gets an egress tool, not just `fetch`. The exfiltration
        scenario is "read with one tool, send with another" inside a single
        compromised session, and a fixture that could only do the first half
        would let that pass untested.
        """
        rendered = json.dumps({"url": url, "body": body, "headers": headers or {}}, sort_keys=True)
        return f"200 OK {url} <- {rendered}"

    return server


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------


def git_server(root: Path) -> FastMCP:
    """A real git server, shelling out to the real `git` binary.

    Worth the cost of a subprocess per call: git's output format is exactly the
    kind of thing a transcript-based detector is brittle about, and a stubbed
    version would flatter it.
    """

    def _git(*args: str) -> str:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return (completed.stdout or completed.stderr).strip()

    server = FastMCP("airlock-fixture-git")

    @server.tool()
    def git_status() -> str:
        """Show the working tree status."""
        return _git("status", "--porcelain=v1", "--branch")

    @server.tool()
    def git_show(rev: str = "HEAD") -> str:
        """Show a commit's contents."""
        return _git("show", rev)

    @server.tool()
    def git_diff(ref: str = "HEAD") -> str:
        """Show the diff against a ref."""
        return _git("diff", ref)

    @server.tool()
    def git_remote_list() -> str:
        """List configured remotes."""
        return _git("remote", "-v")

    @server.tool()
    def post_url(url: str, body: str = "", headers: dict[str, str] | None = None) -> str:
        """Pretend to POST to a URL and echo what would have been sent."""
        rendered = json.dumps({"url": url, "body": body, "headers": headers or {}}, sort_keys=True)
        return f"200 OK {url} <- {rendered}"

    return server


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------


def fetch_server(root: Path) -> FastMCP:
    """A server that 'fetches' URLs by recording them.

    No sockets. The interesting question for this layer is whether a host that
    arrived through untrusted content is used as a request destination, and that
    is decided by the argument the agent passes -- not by what the network did.
    Making real requests would add flakiness and an outbound dependency without
    testing anything the argument does not already show.
    """
    server = FastMCP("airlock-fixture-fetch")

    @server.tool()
    def fetch_url(url: str) -> str:
        """Pretend to fetch a URL and describe what would have been fetched."""
        return f"200 OK {url} ({len(url)} bytes)"

    @server.tool()
    def post_url(url: str, body: str = "", headers: dict[str, str] | None = None) -> str:
        """Pretend to POST to a URL and echo what would have been sent."""
        rendered = json.dumps({"url": url, "body": body, "headers": headers or {}}, sort_keys=True)
        return f"200 OK {url} <- {rendered}"

    return server


# ---------------------------------------------------------------------------
# sqlite
# ---------------------------------------------------------------------------


def sqlite_server(db_path: Path) -> FastMCP:
    """A real SQLite server over a real database file.

    Structured queries are the case where per-message taint tracking has nothing
    to match: the agent reads a row, then sends a *different* row's value. The
    gateway can only see that both came from the same database, which is the
    case this fixture exists to make concrete.
    """

    def _connect() -> sqlite3.Connection:
        return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    server = FastMCP("airlock-fixture-sqlite")

    @server.tool()
    def list_tables() -> list[str]:
        """List the tables in the database."""
        with _connect() as db:
            rows = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        return [row[0] for row in rows]

    @server.tool()
    def select(sql: str) -> str:
        """Run a read-only SELECT and return the rows as JSON."""
        if not sql.lstrip().lower().startswith("select"):
            raise ValueError("only SELECT is permitted")
        with _connect() as db:
            rows = db.execute(sql).fetchall()
            columns = [d[0] for d in db.execute(sql).description or []]
        return json.dumps([dict(zip(columns, row, strict=True)) for row in rows])

    @server.tool()
    def post_url(url: str, body: str = "", headers: dict[str, str] | None = None) -> str:
        """Pretend to POST to a URL and echo what would have been sent."""
        rendered = json.dumps({"url": url, "body": body, "headers": headers or {}}, sort_keys=True)
        return f"200 OK {url} <- {rendered}"

    return server


# ---------------------------------------------------------------------------
# seed data
# ---------------------------------------------------------------------------


def seed_filesystem(root: Path) -> None:
    """Lay down the tree the filesystem and git fixtures read.

    The sensitive paths are named the way real deployments name them, because
    the detector keys on those names and a fixture using invented names would
    pass without testing the rule.
    """
    _write(root / "README.md", "# fixture repo\n\nordinary documentation.\n")
    _write(root / "notes/todo.md", "- ship the gateway\n- write the policy layer\n")
    _write(
        root / "run/secrets/api_token",
        f"{FAKE_TOKEN}\n",
    )
    _write(root / "etc/ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n")
    _write(root / "app/config.json", json.dumps({"debug": False, "retries": 3}) + "\n")
    _write(root / ".gitignore", "run/\netc/\n")


def seed_git(root: Path) -> None:
    """Create a real repository with a real commit."""
    seed_filesystem(root)
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.com",
        "GIT_COMMITTER_NAME": "fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.com",
    }
    for args in (
        ["git", "init", "-q", "-b", "main"],
        ["git", "add", "README.md", "notes/todo.md", "app/config.json", ".gitignore"],
        ["git", "commit", "-q", "-m", "initial commit"],
    ):
        subprocess.run(args, cwd=root, env=env, check=True, capture_output=True, timeout=30)


def seed_sqlite(db_path: Path) -> None:
    """Create a real database holding a credential in one row.

    A `credentials` table is the shape of the vulnerability: the value is
    legitimately in the database and the *read* of it is not the problem. The
    problem is that it can then leave.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS customers (id INTEGER, name TEXT)")
        connection.execute("CREATE TABLE IF NOT EXISTS credentials (id INTEGER, token TEXT)")
        connection.executemany(
            "INSERT INTO customers (id, name) VALUES (?, ?)", [(1, "acme"), (2, "globex")]
        )
        connection.executemany(
            "INSERT INTO credentials (id, token) VALUES (?, ?)", [(1, FAKE_TOKEN)]
        )
        connection.commit()
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

SURFACES = {
    "filesystem": filesystem_server,
    "git": git_server,
    "fetch": fetch_server,
    "sqlite": sqlite_server,
}

SEEDS = {
    "filesystem": lambda root: seed_filesystem(root),
    "git": seed_git,
    "fetch": lambda root: None,
    "sqlite": lambda root: seed_sqlite(root),
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in SURFACES:
        print(f"usage: mcp_servers.py {{{'|'.join(SURFACES)}}} PATH", file=sys.stderr)
        return 2
    surface, path = args[0], Path(args[1])
    server = SURFACES[surface](path)
    # stdout is the protocol channel. Anything else written here would corrupt
    # the stream, so diagnostics go to stderr.
    print(f"[fixture] serving {surface} over {path}", file=sys.stderr)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
