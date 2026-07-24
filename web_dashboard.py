"""Standalone read-only web dashboard for MirrorSec SQLite results."""

from __future__ import annotations

import argparse
import json
import mimetypes
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit


_DEFAULT_PAGE_SIZE = 20
_MAX_PAGE_SIZE = 100
_STATIC_DIR = Path(__file__).resolve().parent / "web"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_int(value: str | None, default: int, *, minimum: int, maximum: int) -> int:
    try:
        result = int(value or "")
    except (TypeError, ValueError):
        return default
    return min(max(result, minimum), maximum)


class DashboardStore:
    """Provide short-lived, read-only snapshots of a live SQLite database."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()

    def _connect(self) -> sqlite3.Connection:
        uri_path = quote(str(self.db_path), safe="/:")
        connection = sqlite3.connect(
            f"file:{uri_path}?mode=ro",
            uri=True,
            timeout=5,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _has_table(connection: sqlite3.Connection, name: str) -> bool:
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (name,),
        ).fetchone()
        return row is not None

    @staticmethod
    def _scalar(
        connection: sqlite3.Connection,
        sql: str,
        parameters: tuple[Any, ...] = (),
    ) -> int:
        row = connection.execute(sql, parameters).fetchone()
        return int(row[0] or 0) if row is not None else 0

    def summary(self) -> dict[str, Any]:
        base: dict[str, Any] = {
            "generated_at": _utc_now(),
            "database": {
                "path": str(self.db_path),
                "name": self.db_path.name,
                "exists": self.db_path.is_file(),
                "size_bytes": (
                    self.db_path.stat().st_size if self.db_path.is_file() else 0
                ),
                "modified_at": (
                    datetime.fromtimestamp(
                        self.db_path.stat().st_mtime,
                        tz=timezone.utc,
                    ).isoformat()
                    if self.db_path.is_file()
                    else ""
                ),
            },
            "history": {
                "issues": 0,
                "commits": 0,
                "analyzed": 0,
                "skipped": 0,
                "failed": 0,
                "fix_commits": 0,
            },
            "findings": {
                "total": 0,
                "critical": 0,
                "high": 0,
                "audits": 0,
                "running": 0,
                "completed": 0,
                "failed": 0,
            },
        }
        if not self.db_path.is_file():
            return base

        with self._connect() as connection:
            if self._has_table(connection, "analyzed_commits"):
                base["history"].update(
                    {
                        "commits": self._scalar(
                            connection, "SELECT COUNT(*) FROM analyzed_commits"
                        ),
                        "analyzed": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM analyzed_commits "
                            "WHERE status = 'analyzed'",
                        ),
                        "skipped": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM analyzed_commits "
                            "WHERE status = 'skipped'",
                        ),
                        "failed": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM analyzed_commits "
                            "WHERE status = 'failed'",
                        ),
                        "fix_commits": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM analyzed_commits "
                            "WHERE vulnerability_fix = 1",
                        ),
                    }
                )
            if self._has_table(connection, "vulnerabilities"):
                base["history"]["issues"] = self._scalar(
                    connection, "SELECT COUNT(*) FROM vulnerabilities"
                )
            if self._has_table(connection, "similar_issue_findings"):
                base["findings"].update(
                    {
                        "total": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM similar_issue_findings",
                        ),
                        "critical": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM similar_issue_findings "
                            "WHERE LOWER(severity) = 'critical'",
                        ),
                        "high": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM similar_issue_findings "
                            "WHERE LOWER(severity) = 'high'",
                        ),
                    }
                )
            if self._has_table(connection, "similar_issue_audits"):
                base["findings"].update(
                    {
                        "audits": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM similar_issue_audits",
                        ),
                        "running": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM similar_issue_audits "
                            "WHERE status = 'running'",
                        ),
                        "completed": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM similar_issue_audits "
                            "WHERE status = 'completed'",
                        ),
                        "failed": self._scalar(
                            connection,
                            "SELECT COUNT(*) FROM similar_issue_audits "
                            "WHERE status = 'failed'",
                        ),
                    }
                )
        return base

    def history_issues(
        self,
        *,
        page: int = 1,
        page_size: int = _DEFAULT_PAGE_SIZE,
        query: str = "",
    ) -> dict[str, Any]:
        page = max(page, 1)
        page_size = min(max(page_size, 1), _MAX_PAGE_SIZE)
        query = query.strip()[:200]
        empty = self._empty_page(page, page_size)
        if not self.db_path.is_file():
            return empty

        with self._connect() as connection:
            if not self._has_table(connection, "vulnerabilities"):
                return empty
            has_commits = self._has_table(connection, "analyzed_commits")
            where_sql = ""
            parameters: list[Any] = []
            if query:
                where_sql = (
                    "WHERE v.commit_hash LIKE ? "
                    "OR v.description LIKE ? "
                    "OR v.root_cause LIKE ? "
                )
                search = f"%{query}%"
                parameters.extend((search, search, search))
                if has_commits:
                    where_sql += (
                        "OR a.subject LIKE ? "
                        "OR a.author_name LIKE ? "
                        "OR a.author_email LIKE ? "
                    )
                    parameters.extend((search, search, search))

            total = self._scalar(
                connection,
                "SELECT COUNT(*) FROM vulnerabilities AS v "
                + (
                    "LEFT JOIN analyzed_commits AS a "
                    "ON a.commit_hash = v.commit_hash "
                    if has_commits
                    else ""
                )
                + where_sql,
                tuple(parameters),
            )
            commit_fields = (
                "COALESCE(a.subject, '') AS subject, "
                "COALESCE(a.author_name, '') AS author_name, "
                "COALESCE(a.author_email, '') AS author_email, "
                "COALESCE(a.authored_at, '') AS authored_at, "
                "COALESCE(a.analyzed_at, '') AS analyzed_at "
                if has_commits
                else
                "'' AS subject, '' AS author_name, '' AS author_email, "
                "'' AS authored_at, '' AS analyzed_at "
            )
            sql = (
                "SELECT v.commit_hash, v.issue_number, v.description, "
                "v.root_cause, v.original_code, v.created_at, "
                + commit_fields
                + "FROM vulnerabilities AS v "
                + (
                    "LEFT JOIN analyzed_commits AS a "
                    "ON a.commit_hash = v.commit_hash "
                    if has_commits
                    else ""
                )
                + where_sql
                + "ORDER BY v.created_at DESC, v.commit_hash, v.issue_number "
                "LIMIT ? OFFSET ?"
            )
            offset = (page - 1) * page_size
            rows = connection.execute(
                sql,
                (*parameters, page_size, offset),
            ).fetchall()

        items = [dict(row) for row in rows]
        for item in items:
            item["issue_id"] = (
                f"{str(item['commit_hash'])[:12]}#{item['issue_number']}"
            )
        return self._page(items, total, page, page_size)

    def similar_findings(
        self,
        *,
        page: int = 1,
        page_size: int = _DEFAULT_PAGE_SIZE,
        query: str = "",
        severity: str = "",
    ) -> dict[str, Any]:
        page = max(page, 1)
        page_size = min(max(page_size, 1), _MAX_PAGE_SIZE)
        query = query.strip()[:200]
        severity = severity.strip().lower()[:32]
        empty = self._empty_page(page, page_size)
        if not self.db_path.is_file():
            return empty

        with self._connect() as connection:
            if not self._has_table(connection, "similar_issue_findings"):
                return empty
            has_vulnerabilities = self._has_table(connection, "vulnerabilities")
            conditions: list[str] = []
            parameters: list[Any] = []
            if query:
                search = f"%{query}%"
                conditions.append(
                    "("
                    "f.title LIKE ? OR f.code_location LIKE ? "
                    "OR f.root_cause LIKE ? OR f.evidence LIKE ? "
                    "OR f.source_commit_hash LIKE ?"
                    + (" OR v.description LIKE ?" if has_vulnerabilities else "")
                    + ")"
                )
                parameters.extend((search, search, search, search, search))
                if has_vulnerabilities:
                    parameters.append(search)
            if severity:
                conditions.append("LOWER(f.severity) = ?")
                parameters.append(severity)
            where_sql = (
                "WHERE " + " AND ".join(conditions) + " " if conditions else ""
            )
            join_sql = (
                "LEFT JOIN vulnerabilities AS v "
                "ON v.commit_hash = f.source_commit_hash "
                "AND v.issue_number = f.source_issue_number "
                if has_vulnerabilities
                else ""
            )
            total = self._scalar(
                connection,
                "SELECT COUNT(*) FROM similar_issue_findings AS f "
                + join_sql
                + where_sql,
                tuple(parameters),
            )
            source_field = (
                "COALESCE(v.description, '') AS source_description "
                if has_vulnerabilities
                else "'' AS source_description "
            )
            sql = (
                "SELECT f.source_commit_hash, f.source_issue_number, "
                "f.code_path, f.finding_number, f.target_revision, "
                "f.code_location, f.similar_issue_exists, f.severity, "
                "f.title, f.root_cause, f.evidence, f.attack_path, "
                "f.similarity_analysis, f.difference_analysis, "
                "f.recommendation, f.confidence, f.created_at, "
                + source_field
                + "FROM similar_issue_findings AS f "
                + join_sql
                + where_sql
                + "ORDER BY f.created_at DESC, f.source_commit_hash, "
                "f.source_issue_number, f.finding_number "
                "LIMIT ? OFFSET ?"
            )
            offset = (page - 1) * page_size
            rows = connection.execute(
                sql,
                (*parameters, page_size, offset),
            ).fetchall()

        items = [dict(row) for row in rows]
        for item in items:
            item["source_issue_id"] = (
                f"{str(item['source_commit_hash'])[:12]}"
                f"#{item['source_issue_number']}"
            )
        return self._page(items, total, page, page_size)

    @staticmethod
    def _empty_page(page: int, page_size: int) -> dict[str, Any]:
        return DashboardStore._page([], 0, page, page_size)

    @staticmethod
    def _page(
        items: list[dict[str, Any]],
        total: int,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        pages = max((total + page_size - 1) // page_size, 1)
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
        }


class _DashboardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _handler_class(
    store: DashboardStore,
    static_dir: Path,
) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "MirrorSecDashboard/1.0"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path.startswith("/api/"):
                self._serve_api(parsed.path, parse_qs(parsed.query))
                return
            self._serve_static(parsed.path)

        def do_HEAD(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path.startswith("/api/"):
                self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
                return
            self._serve_static(parsed.path, include_body=False)

        def log_message(self, format_string: str, *args: Any) -> None:
            del format_string, args

        def _serve_api(
            self,
            path: str,
            parameters: dict[str, list[str]],
        ) -> None:
            try:
                if path == "/api/summary":
                    self._send_json(HTTPStatus.OK, store.summary())
                    return

                page = _as_int(
                    self._first(parameters, "page"),
                    1,
                    minimum=1,
                    maximum=1_000_000,
                )
                page_size = _as_int(
                    self._first(parameters, "page_size"),
                    _DEFAULT_PAGE_SIZE,
                    minimum=1,
                    maximum=_MAX_PAGE_SIZE,
                )
                query = self._first(parameters, "query") or ""
                if path == "/api/history":
                    self._send_json(
                        HTTPStatus.OK,
                        store.history_issues(
                            page=page,
                            page_size=page_size,
                            query=query,
                        ),
                    )
                    return
                if path == "/api/findings":
                    self._send_json(
                        HTTPStatus.OK,
                        store.similar_findings(
                            page=page,
                            page_size=page_size,
                            query=query,
                            severity=self._first(parameters, "severity") or "",
                        ),
                    )
                    return
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "API endpoint not found"},
                )
            except (OSError, sqlite3.Error) as exc:
                self._send_json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {
                        "error": "数据库暂时不可读",
                        "detail": str(exc),
                        "generated_at": _utc_now(),
                    },
                )

        @staticmethod
        def _first(
            parameters: dict[str, list[str]],
            name: str,
        ) -> str | None:
            values = parameters.get(name)
            return values[0] if values else None

        def _serve_static(
            self,
            url_path: str,
            *,
            include_body: bool = True,
        ) -> None:
            relative = unquote(url_path).lstrip("/") or "index.html"
            if relative.endswith("/"):
                relative += "index.html"
            candidate = (static_dir / relative).resolve()
            try:
                candidate.relative_to(static_dir)
            except ValueError:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if not candidate.is_file():
                self.send_error(HTTPStatus.NOT_FOUND)
                return

            content = candidate.read_bytes()
            content_type = mimetypes.guess_type(candidate.name)[0]
            self.send_response(HTTPStatus.OK)
            self.send_header(
                "Content-Type",
                f"{content_type or 'application/octet-stream'}; charset=utf-8",
            )
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            if include_body:
                self.wfile.write(content)

        def _send_json(self, status: HTTPStatus, payload: Any) -> None:
            content = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(content)

    return DashboardHandler


@dataclass
class DashboardServer:
    """Running dashboard server plus lifecycle helpers."""

    server: _DashboardHTTPServer
    thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return str(self.server.server_address[0])

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def url(self) -> str:
        display_host = "127.0.0.1" if self.host in {"0.0.0.0", "::"} else self.host
        return f"http://{display_host}:{self.port}"

    def serve_forever(self) -> None:
        self.server.serve_forever(poll_interval=0.25)

    def start(self) -> "DashboardServer":
        if self.thread is not None and self.thread.is_alive():
            return self
        self.thread = threading.Thread(
            target=self.serve_forever,
            name="mirrorsec-web-dashboard",
            daemon=True,
        )
        self.thread.start()
        return self

    def close(self) -> None:
        if self.thread is not None and self.thread.is_alive():
            self.server.shutdown()
            self.thread.join(timeout=5)
        self.server.server_close()


def create_dashboard_server(
    db_path: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    static_dir: str | Path = _STATIC_DIR,
) -> DashboardServer:
    static_path = Path(static_dir).resolve()
    if not static_path.is_dir():
        raise ValueError(f"Web 静态资源目录不存在：{static_path}")
    store = DashboardStore(db_path)
    server = _DashboardHTTPServer(
        (host, port),
        _handler_class(store, static_path),
    )
    return DashboardServer(server=server)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="独立启动 MirrorSec 实时结果看板（只读访问 SQLite）。"
    )
    parser.add_argument(
        "--db",
        default="git_history_analysis.sqlite3",
        help="MirrorSec SQLite 数据库路径。",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="监听地址，默认 127.0.0.1。",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="监听端口，默认 8765。",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    if not 0 <= args.port <= 65535:
        print("[web] FAILED port must be between 0 and 65535", flush=True)
        return 2
    try:
        dashboard = create_dashboard_server(
            args.db,
            host=args.host,
            port=args.port,
        )
    except (OSError, ValueError) as exc:
        print(f"[web] FAILED {type(exc).__name__}: {exc}", flush=True)
        return 1

    print(
        f"[web] START url={dashboard.url} "
        f"db={Path(args.db).expanduser().resolve()}",
        flush=True,
    )
    print("[web] 按 Ctrl+C 停止", flush=True)
    try:
        dashboard.serve_forever()
    except KeyboardInterrupt:
        print("\n[web] STOP", flush=True)
    finally:
        dashboard.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
