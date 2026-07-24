"""Run git-history analysis and incremental similar-issue audits together."""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

import find_similar_issue.analyzer as similar_issue_module
import git_history_analysis.analyzer as git_history_module
from task_agent import opencode_task_context, shutdown_opencode
from task_agent.standalone import ensure_opencode_configuration


_CAPABILITIES = ("low", "medium", "high")
_POLL_INTERVAL_SECONDS = 0.5


@dataclass(frozen=True)
class _HistoricalIssue:
    commit_hash: str
    issue_number: int
    description: str
    root_cause: str
    original_code: str

    @property
    def key(self) -> tuple[str, int]:
        return (self.commit_hash, self.issue_number)

    @property
    def display_id(self) -> str:
        return f"{self.commit_hash[:12]}#{self.issue_number}"


@dataclass
class _SimilarAuditSummary:
    scheduled: int = 0
    completed: int = 0
    failed: int = 0
    findings_saved: int = 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "并发运行 Git 历史安全审计和数据库驱动的同类问题排查，"
            "并将确认的问题保存到同一个 SQLite 数据库。"
        ),
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="待审计 Git 代码仓路径。",
    )
    parser.add_argument(
        "--db",
        default="git_history_analysis.sqlite3",
        help="历史问题和同类问题结果数据库，默认 git_history_analysis.sqlite3。",
    )
    parser.add_argument(
        "--history-concurrency",
        type=int,
        default=4,
        help="Git 历史审计并发度，默认 4。",
    )
    parser.add_argument(
        "--history-capability",
        choices=_CAPABILITIES,
        default="medium",
        help="Git 历史审计要求的最低模型能力，默认 medium。",
    )
    parser.add_argument(
        "--similar-concurrency",
        type=int,
        default=4,
        help=(
            "同类问题排查的全局模型任务并发上限，覆盖候选发现和所有"
            "候选点审计，默认 4。"
        ),
    )
    parser.add_argument(
        "--similar-capability",
        choices=_CAPABILITIES,
        default="high",
        help="同类问题排查要求的最低模型能力，默认 high。",
    )
    parser.add_argument(
        "--revision-range",
        default="HEAD",
        help="传给 Git 历史审计的 revision range，默认 HEAD。",
    )
    parser.add_argument(
        "--config-path",
        default=None,
        help="Task Agent 独立运行配置 YAML；默认使用环境变量或当前目录配置。",
    )
    return parser


def _validate_cli_args(args: argparse.Namespace) -> tuple[Path, Path]:
    if args.history_concurrency < 1:
        raise ValueError("--history-concurrency must be >= 1")
    if args.similar_concurrency < 1:
        raise ValueError("--similar-concurrency must be >= 1")

    repo_path = Path(args.repo).expanduser().resolve()
    if not repo_path.is_dir():
        raise ValueError(f"待审计代码仓不存在或不是目录：{repo_path}")
    _git(repo_path, "rev-parse", "--show-toplevel")

    db_path = Path(args.db).expanduser()
    if not db_path.is_absolute():
        db_path = Path.cwd() / db_path
    db_path = db_path.resolve()
    return repo_path, db_path


def _git(repo_path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_path,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        error = " ".join(result.stderr.split())
        raise ValueError(f"{repo_path} 不是有效的 Git 代码仓：{error}")
    return result.stdout.strip()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect_database(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def _initialize_similar_audit_store(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = _connect_database(db_path)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS similar_issue_audits (
                source_commit_hash TEXT NOT NULL,
                source_issue_number INTEGER NOT NULL,
                code_path TEXT NOT NULL,
                target_revision TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL DEFAULT '',
                completed_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                error TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (
                    source_commit_hash,
                    source_issue_number,
                    code_path
                )
            );

            CREATE TABLE IF NOT EXISTS similar_issue_findings (
                source_commit_hash TEXT NOT NULL,
                source_issue_number INTEGER NOT NULL,
                code_path TEXT NOT NULL,
                finding_number INTEGER NOT NULL,
                target_revision TEXT NOT NULL DEFAULT '',
                code_location TEXT NOT NULL,
                similar_issue_exists INTEGER NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                root_cause TEXT NOT NULL,
                evidence TEXT NOT NULL,
                attack_path TEXT NOT NULL,
                similarity_analysis TEXT NOT NULL,
                difference_analysis TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                confidence TEXT NOT NULL,
                created_at TEXT NOT NULL,
                raw_result_json TEXT NOT NULL,
                PRIMARY KEY (
                    source_commit_hash,
                    source_issue_number,
                    code_path,
                    finding_number
                )
            );

            CREATE INDEX IF NOT EXISTS idx_similar_issue_audits_status
                ON similar_issue_audits(status);
            CREATE INDEX IF NOT EXISTS idx_similar_issue_findings_location
                ON similar_issue_findings(code_location);
            """
        )
        now = _utc_now()
        connection.execute(
            """
            UPDATE similar_issue_audits
            SET status = 'failed',
                completed_at = ?,
                updated_at = ?,
                error = 'previous program run was interrupted'
            WHERE status = 'running'
            """,
            (now, now),
        )
        connection.commit()
    finally:
        connection.close()


def _load_pending_issues(
    db_path: Path,
    *,
    code_path: str,
    attempted: set[tuple[str, int]],
) -> list[_HistoricalIssue]:
    connection = _connect_database(db_path)
    try:
        try:
            rows = connection.execute(
                """
                SELECT
                    v.commit_hash,
                    v.issue_number,
                    v.description,
                    v.root_cause,
                    v.original_code
                FROM vulnerabilities AS v
                LEFT JOIN similar_issue_audits AS a
                  ON a.source_commit_hash = v.commit_hash
                 AND a.source_issue_number = v.issue_number
                 AND a.code_path = ?
                WHERE a.status IS NULL OR a.status != 'completed'
                ORDER BY v.created_at, v.commit_hash, v.issue_number
                """,
                (code_path,),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table: vulnerabilities" in str(exc):
                return []
            raise
    finally:
        connection.close()

    issues: list[_HistoricalIssue] = []
    for row in rows:
        issue = _HistoricalIssue(
            commit_hash=str(row["commit_hash"]),
            issue_number=int(row["issue_number"]),
            description=str(row["description"]),
            root_cause=str(row["root_cause"]),
            original_code=str(row["original_code"]),
        )
        if issue.key not in attempted:
            issues.append(issue)
    return issues


def _mark_similar_audit_running(
    db_path: Path,
    *,
    issue: _HistoricalIssue,
    code_path: str,
    target_revision: str,
) -> None:
    now = _utc_now()
    connection = _connect_database(db_path)
    try:
        with connection:
            connection.execute(
                """
                INSERT INTO similar_issue_audits (
                    source_commit_hash,
                    source_issue_number,
                    code_path,
                    target_revision,
                    status,
                    attempts,
                    findings_count,
                    started_at,
                    completed_at,
                    updated_at,
                    error
                )
                VALUES (?, ?, ?, ?, 'running', 1, 0, ?, '', ?, '')
                ON CONFLICT (
                    source_commit_hash,
                    source_issue_number,
                    code_path
                )
                DO UPDATE SET
                    target_revision = excluded.target_revision,
                    status = 'running',
                    attempts = similar_issue_audits.attempts + 1,
                    findings_count = 0,
                    started_at = excluded.started_at,
                    completed_at = '',
                    updated_at = excluded.updated_at,
                    error = ''
                """,
                (
                    issue.commit_hash,
                    issue.issue_number,
                    code_path,
                    target_revision,
                    now,
                    now,
                ),
            )
    finally:
        connection.close()


def _save_similar_audit_findings(
    db_path: Path,
    *,
    issue: _HistoricalIssue,
    code_path: str,
    target_revision: str,
    findings: list[dict[str, Any]],
) -> None:
    now = _utc_now()
    connection = _connect_database(db_path)
    try:
        with connection:
            connection.execute(
                """
                DELETE FROM similar_issue_findings
                WHERE source_commit_hash = ?
                  AND source_issue_number = ?
                  AND code_path = ?
                """,
                (issue.commit_hash, issue.issue_number, code_path),
            )
            for finding_number, finding in enumerate(findings, start=1):
                connection.execute(
                    """
                    INSERT INTO similar_issue_findings (
                        source_commit_hash,
                        source_issue_number,
                        code_path,
                        finding_number,
                        target_revision,
                        code_location,
                        similar_issue_exists,
                        severity,
                        title,
                        root_cause,
                        evidence,
                        attack_path,
                        similarity_analysis,
                        difference_analysis,
                        recommendation,
                        confidence,
                        created_at,
                        raw_result_json
                    )
                    VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        issue.commit_hash,
                        issue.issue_number,
                        code_path,
                        finding_number,
                        target_revision,
                        str(finding.get("code_location") or ""),
                        int(bool(finding.get("similar_issue_exists"))),
                        str(finding.get("severity") or "none"),
                        str(finding.get("title") or ""),
                        str(finding.get("root_cause") or ""),
                        str(finding.get("evidence") or ""),
                        str(finding.get("attack_path") or ""),
                        str(finding.get("similarity_analysis") or ""),
                        str(finding.get("difference_analysis") or ""),
                        str(finding.get("recommendation") or ""),
                        str(finding.get("confidence") or "low"),
                        now,
                        json.dumps(finding, ensure_ascii=False, sort_keys=True),
                    ),
                )
            connection.execute(
                """
                UPDATE similar_issue_audits
                SET status = 'completed',
                    findings_count = ?,
                    completed_at = ?,
                    updated_at = ?,
                    error = ''
                WHERE source_commit_hash = ?
                  AND source_issue_number = ?
                  AND code_path = ?
                """,
                (
                    len(findings),
                    now,
                    now,
                    issue.commit_hash,
                    issue.issue_number,
                    code_path,
                ),
            )
    finally:
        connection.close()


def _mark_similar_audit_failed(
    db_path: Path,
    *,
    issue: _HistoricalIssue,
    code_path: str,
    error: str,
) -> None:
    now = _utc_now()
    connection = _connect_database(db_path)
    try:
        with connection:
            connection.execute(
                """
                UPDATE similar_issue_audits
                SET status = 'failed',
                    completed_at = ?,
                    updated_at = ?,
                    error = ?
                WHERE source_commit_hash = ?
                  AND source_issue_number = ?
                  AND code_path = ?
                """,
                (
                    now,
                    now,
                    error[:4000],
                    issue.commit_hash,
                    issue.issue_number,
                    code_path,
                ),
            )
    finally:
        connection.close()


async def _audit_one_historical_issue(
    *,
    db_path: Path,
    repo_path: Path,
    target_revision: str,
    issue: _HistoricalIssue,
) -> tuple[bool, int]:
    print(f"[similar] START issue={issue.display_id}", flush=True)
    try:
        findings = await similar_issue_module.run_similar_issues_audit(
            issue_description=issue.description,
            issue_root_analysis=issue.root_cause,
            issue_code=issue.original_code,
            code_path=str(repo_path),
        )
        _save_similar_audit_findings(
            db_path,
            issue=issue,
            code_path=str(repo_path),
            target_revision=target_revision,
            findings=findings,
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        try:
            _mark_similar_audit_failed(
                db_path,
                issue=issue,
                code_path=str(repo_path),
                error=error,
            )
        finally:
            print(
                f"[similar] FAILED issue={issue.display_id} error={error}",
                flush=True,
            )
        return False, 0

    print(
        f"[similar] DONE issue={issue.display_id} findings={len(findings)}",
        flush=True,
    )
    return True, len(findings)


async def _run_similar_issue_scheduler(
    *,
    db_path: Path,
    repo_path: Path,
    target_revision: str,
    concurrency: int,
    history_task: asyncio.Task[Any],
) -> _SimilarAuditSummary:
    summary = _SimilarAuditSummary()
    attempted: set[tuple[str, int]] = set()
    active: dict[asyncio.Task[tuple[bool, int]], _HistoricalIssue] = {}

    while True:
        capacity = concurrency - len(active)
        if capacity > 0:
            pending = _load_pending_issues(
                db_path,
                code_path=str(repo_path),
                attempted=attempted,
            )
            for issue in pending[:capacity]:
                _mark_similar_audit_running(
                    db_path,
                    issue=issue,
                    code_path=str(repo_path),
                    target_revision=target_revision,
                )
                attempted.add(issue.key)
                summary.scheduled += 1
                task = asyncio.create_task(
                    _audit_one_historical_issue(
                        db_path=db_path,
                        repo_path=repo_path,
                        target_revision=target_revision,
                        issue=issue,
                    )
                )
                active[task] = issue

        if not active:
            if history_task.done():
                remaining = _load_pending_issues(
                    db_path,
                    code_path=str(repo_path),
                    attempted=attempted,
                )
                if not remaining:
                    break
                continue
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
            continue

        done, _ = await asyncio.wait(
            set(active),
            timeout=_POLL_INTERVAL_SECONDS,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            active.pop(task, None)
            success, findings_count = await task
            if success:
                summary.completed += 1
                summary.findings_saved += findings_count
            else:
                summary.failed += 1

    return summary


def _make_capability_task_runner(
    capability: str,
    *,
    concurrency_limiter: asyncio.Semaphore | None = None,
) -> Callable[..., Any]:
    async def run_task(
        *,
        task_name: str,
        task_type: str,
        prompt: str,
        required_capability: str,
        output_schema: dict[str, Any] | None = None,
        invalid_json_retry_count: int = 2,
        invalid_json_retry_prompt: str | None = None,
        session_id: str | None = None,
        **_: Any,
    ) -> Any:
        # Task Agent's scheduler already supports medium; its public compatibility
        # wrapper currently narrows inputs to low/high. Calling the scheduler here
        # keeps all capability adaptation local to this main program.
        from task_agent.task_service import _run_component_task

        async def invoke() -> Any:
            return await _run_component_task(
                task_name=task_name,
                task_type=task_type,
                prompt=prompt,
                required_capability=capability,
                output_schema=output_schema,
                invalid_json_retry_count=invalid_json_retry_count,
                invalid_json_retry_prompt=invalid_json_retry_prompt,
                session_id=session_id,
            )

        if concurrency_limiter is None:
            return await invoke()
        async with concurrency_limiter:
            return await invoke()

    return run_task


@contextmanager
def _use_requested_model_capabilities(
    *,
    history_capability: str,
    similar_capability: str,
    similar_concurrency: int,
) -> Iterator[None]:
    original_history_runner = git_history_module.run_opencode_task
    original_similar_runner = similar_issue_module.run_opencode_task
    original_find_similar_issue = similar_issue_module.find_similar_issue
    similar_limiter = asyncio.Semaphore(similar_concurrency)

    async def find_similar_issue_with_concurrency(
        known_issue: Any,
        **overrides: Any,
    ) -> Any:
        overrides["concurrency"] = similar_concurrency
        return await original_find_similar_issue(known_issue, **overrides)

    git_history_module.run_opencode_task = _make_capability_task_runner(
        history_capability
    )
    similar_issue_module.run_opencode_task = _make_capability_task_runner(
        similar_capability,
        concurrency_limiter=similar_limiter,
    )
    similar_issue_module.find_similar_issue = find_similar_issue_with_concurrency
    try:
        yield
    finally:
        git_history_module.run_opencode_task = original_history_runner
        similar_issue_module.run_opencode_task = original_similar_runner
        similar_issue_module.find_similar_issue = original_find_similar_issue


async def _run_history_analysis(
    *,
    repo_path: Path,
    db_path: Path,
    revision_range: str,
    concurrency: int,
    config_path: str | None,
) -> Any:
    print(
        f"[history] START repo={repo_path} concurrency={concurrency}",
        flush=True,
    )
    summary = await git_history_module.analyze_git_history(
        git_history_module.GitHistoryAnalysisOptions(
            repo_path=repo_path,
            db_path=db_path,
            revision_range=revision_range,
            concurrency=concurrency,
            required_capability="high",
            config_path=config_path,
            output=None,
        )
    )
    print(
        "[history] DONE "
        f"analyzed={summary.analyzed_commits} "
        f"failed={summary.failed_commits} "
        f"issues_saved={summary.vulnerabilities_saved}",
        flush=True,
    )
    return summary


async def _run(args: argparse.Namespace) -> int:
    repo_path, db_path = _validate_cli_args(args)
    target_revision = _git(repo_path, "rev-parse", "HEAD")
    _initialize_similar_audit_store(db_path)

    print(
        "[main] START "
        f"repo={repo_path} db={db_path} "
        f"history_capability={args.history_capability} "
        f"similar_capability={args.similar_capability}",
        flush=True,
    )

    ensure_opencode_configuration(args.config_path)
    history_error: BaseException | None = None
    similar_summary = _SimilarAuditSummary()

    with tempfile.TemporaryDirectory(prefix="mirrorsec-task-") as work_dir:
        with opencode_task_context(
            project_dir=repo_path,
            work_dir=work_dir,
            config_path=args.config_path,
        ):
            with _use_requested_model_capabilities(
                history_capability=args.history_capability,
                similar_capability=args.similar_capability,
                similar_concurrency=args.similar_concurrency,
            ):
                history_task = asyncio.create_task(
                    _run_history_analysis(
                        repo_path=repo_path,
                        db_path=db_path,
                        revision_range=args.revision_range,
                        concurrency=args.history_concurrency,
                        config_path=args.config_path,
                    )
                )
                similar_summary = await _run_similar_issue_scheduler(
                    db_path=db_path,
                    repo_path=repo_path,
                    target_revision=target_revision,
                    concurrency=args.similar_concurrency,
                    history_task=history_task,
                )
                try:
                    await history_task
                except BaseException as exc:
                    history_error = exc

    print(
        "[similar] DONE "
        f"scheduled={similar_summary.scheduled} "
        f"completed={similar_summary.completed} "
        f"failed={similar_summary.failed} "
        f"findings_saved={similar_summary.findings_saved}",
        flush=True,
    )
    if history_error is not None:
        print(
            f"[history] FAILED error={type(history_error).__name__}: {history_error}",
            flush=True,
        )
    print("[main] DONE", flush=True)
    return int(history_error is not None or similar_summary.failed > 0)


async def _amain(args: argparse.Namespace) -> int:
    try:
        return await _run(args)
    finally:
        try:
            await shutdown_opencode()
        except Exception as exc:
            print(
                f"[main] WARN shutdown failed: {type(exc).__name__}: {exc}",
                flush=True,
            )


def main() -> int:
    args = _build_parser().parse_args()
    try:
        return asyncio.run(_amain(args))
    except KeyboardInterrupt:
        print("[main] CANCELLED", flush=True)
        return 130
    except Exception as exc:
        print(f"[main] FAILED error={type(exc).__name__}: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
