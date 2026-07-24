"""Git commit vulnerability-fix analysis backed by run_opencode_task only."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from task_agent import run_opencode_task


ANALYSIS_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "issues": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "问题场景、触发方式和安全影响的准确描述。",
                        "minLength": 1,
                    },
                    "root_cause": {
                        "type": "string",
                        "description": (
                            "结合具体函数、变量、数据流、缺失的安全约束和危险操作"
                            "说明完整问题因果链。"
                        ),
                        "minLength": 1,
                    },
                    "original_code": {
                        "type": "string",
                        "description": "修复前真正导致问题且包含必要上下文的原始代码。",
                        "minLength": 1,
                    },
                },
                "required": [
                    "description",
                    "root_cause",
                    "original_code",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["issues"],
    "additionalProperties": False,
}

_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)


@dataclass(frozen=True)
class GitHistoryAnalysisOptions:
    """Options for one git history analysis run."""

    repo_path: str | os.PathLike[str] = "."
    db_path: str | os.PathLike[str] = "git_history_analysis.sqlite3"
    revision_range: str = "HEAD"
    since: str | None = None
    until: str | None = None
    max_commits: int | None = None
    concurrency: int = 4
    include_merges: bool = False
    skip_analyzed: bool = True
    diff_context_lines: int = 80
    max_patch_chars: int = 120_000
    max_original_code_chars: int = 60_000
    max_hunks_per_file: int = 24
    git_timeout: float = 60.0
    required_capability: Literal["low", "high"] = "high"
    config_path: str | os.PathLike[str] | None = None
    output: Callable[[str], Any] | None = None
    cancel_event: Any = None


@dataclass(frozen=True)
class GitHistoryAnalysisSummary:
    """Counters returned by analyze_git_history."""

    database_path: str
    total_commits: int = 0
    scheduled_commits: int = 0
    analyzed_commits: int = 0
    skipped_commits: int = 0
    failed_commits: int = 0
    security_related_commits: int = 0
    vulnerability_fix_commits: int = 0
    vulnerabilities_saved: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "database_path": self.database_path,
            "total_commits": self.total_commits,
            "scheduled_commits": self.scheduled_commits,
            "analyzed_commits": self.analyzed_commits,
            "skipped_commits": self.skipped_commits,
            "failed_commits": self.failed_commits,
            "security_related_commits": self.security_related_commits,
            "vulnerability_fix_commits": self.vulnerability_fix_commits,
            "vulnerabilities_saved": self.vulnerabilities_saved,
        }


@dataclass(frozen=True)
class _CommitInfo:
    commit_hash: str
    parents: tuple[str, ...]
    author_name: str
    author_email: str
    authored_at: str
    subject: str
    body: str


@dataclass(frozen=True)
class _CommitPayload:
    info: _CommitInfo
    patch: str = ""
    original_code: str = ""
    patch_truncated: bool = False
    original_code_truncated: bool = False
    skip_reason: str = ""


@dataclass(frozen=True)
class _CommitOutcome:
    status: Literal["analyzed", "skipped", "failed"]
    security_related: bool = False
    vulnerability_fix: bool = False
    vulnerabilities_saved: int = 0


class _SummaryBuilder:
    def __init__(self, *, database_path: str, total_commits: int, scheduled_commits: int):
        self.database_path = database_path
        self.total_commits = total_commits
        self.scheduled_commits = scheduled_commits
        self.analyzed_commits = 0
        self.skipped_commits = 0
        self.failed_commits = 0
        self.security_related_commits = 0
        self.vulnerability_fix_commits = 0
        self.vulnerabilities_saved = 0

    def add_outcome(self, outcome: _CommitOutcome) -> None:
        if outcome.status == "analyzed":
            self.analyzed_commits += 1
        elif outcome.status == "skipped":
            self.skipped_commits += 1
        elif outcome.status == "failed":
            self.failed_commits += 1
        if outcome.security_related:
            self.security_related_commits += 1
        if outcome.vulnerability_fix:
            self.vulnerability_fix_commits += 1
        self.vulnerabilities_saved += outcome.vulnerabilities_saved

    def build(self) -> GitHistoryAnalysisSummary:
        return GitHistoryAnalysisSummary(
            database_path=self.database_path,
            total_commits=self.total_commits,
            scheduled_commits=self.scheduled_commits,
            analyzed_commits=self.analyzed_commits,
            skipped_commits=self.skipped_commits,
            failed_commits=self.failed_commits,
            security_related_commits=self.security_related_commits,
            vulnerability_fix_commits=self.vulnerability_fix_commits,
            vulnerabilities_saved=self.vulnerabilities_saved,
        )


class _SQLiteResultStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._connection: sqlite3.Connection | None = None

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("SQLite store is not open")
        return self._connection

    def open(self) -> None:
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.db_path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._initialize()

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS analyzed_commits (
                commit_hash TEXT PRIMARY KEY,
                analyzed_at TEXT NOT NULL,
                status TEXT NOT NULL,
                security_related INTEGER NOT NULL DEFAULT 0,
                vulnerability_fix INTEGER NOT NULL DEFAULT 0,
                summary TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT '',
                subject TEXT NOT NULL DEFAULT '',
                author_name TEXT NOT NULL DEFAULT '',
                author_email TEXT NOT NULL DEFAULT '',
                authored_at TEXT NOT NULL DEFAULT '',
                parent_hashes TEXT NOT NULL DEFAULT '',
                patch_truncated INTEGER NOT NULL DEFAULT 0,
                original_code_truncated INTEGER NOT NULL DEFAULT 0,
                raw_result_json TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                issue_number INTEGER NOT NULL,
                commit_hash TEXT NOT NULL,
                description TEXT NOT NULL,
                root_cause TEXT NOT NULL,
                original_code TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (commit_hash, issue_number),
                FOREIGN KEY(commit_hash) REFERENCES analyzed_commits(commit_hash)
            );

            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_commit_hash
                ON vulnerabilities(commit_hash);
            CREATE INDEX IF NOT EXISTS idx_analyzed_commits_status
                ON analyzed_commits(status);
            """
        )
        self.connection.commit()

    def has_completed_analysis(self, commit_hash: str) -> bool:
        row = self.connection.execute(
            """
            SELECT status
            FROM analyzed_commits
            WHERE commit_hash = ?
              AND status IN ('analyzed', 'skipped')
            """,
            (commit_hash,),
        ).fetchone()
        return row is not None

    def record_skipped(self, payload: _CommitPayload) -> None:
        info = payload.info
        self.connection.execute(
            """
            INSERT INTO analyzed_commits (
                commit_hash,
                analyzed_at,
                status,
                summary,
                error,
                subject,
                author_name,
                author_email,
                authored_at,
                parent_hashes,
                patch_truncated,
                original_code_truncated
            )
            VALUES (?, ?, 'skipped', ?, '', ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(commit_hash) DO UPDATE SET
                analyzed_at = excluded.analyzed_at,
                status = excluded.status,
                security_related = 0,
                vulnerability_fix = 0,
                summary = excluded.summary,
                error = '',
                subject = excluded.subject,
                author_name = excluded.author_name,
                author_email = excluded.author_email,
                authored_at = excluded.authored_at,
                parent_hashes = excluded.parent_hashes,
                patch_truncated = excluded.patch_truncated,
                original_code_truncated = excluded.original_code_truncated,
                raw_result_json = ''
            """,
            (
                info.commit_hash,
                _utc_now(),
                payload.skip_reason,
                info.subject,
                info.author_name,
                info.author_email,
                info.authored_at,
                " ".join(info.parents),
                int(payload.patch_truncated),
                int(payload.original_code_truncated),
            ),
        )
        self.connection.commit()

    def record_failure(self, info: _CommitInfo | None, commit_hash: str, error: str) -> None:
        subject = info.subject if info is not None else ""
        author_name = info.author_name if info is not None else ""
        author_email = info.author_email if info is not None else ""
        authored_at = info.authored_at if info is not None else ""
        parents = " ".join(info.parents) if info is not None else ""
        self.connection.execute(
            """
            INSERT INTO analyzed_commits (
                commit_hash,
                analyzed_at,
                status,
                error,
                subject,
                author_name,
                author_email,
                authored_at,
                parent_hashes
            )
            VALUES (?, ?, 'failed', ?, ?, ?, ?, ?, ?)
            ON CONFLICT(commit_hash) DO UPDATE SET
                analyzed_at = excluded.analyzed_at,
                status = excluded.status,
                security_related = 0,
                vulnerability_fix = 0,
                summary = '',
                error = excluded.error,
                subject = excluded.subject,
                author_name = excluded.author_name,
                author_email = excluded.author_email,
                authored_at = excluded.authored_at,
                parent_hashes = excluded.parent_hashes,
                raw_result_json = ''
            """,
            (
                commit_hash,
                _utc_now(),
                error[:4000],
                subject,
                author_name,
                author_email,
                authored_at,
                parents,
            ),
        )
        self.connection.commit()

    def record_analysis(
        self,
        payload: _CommitPayload,
        issues: list[dict[str, str]],
    ) -> int:
        info = payload.info
        vulnerability_fix = bool(issues)
        summary = f"确认修复 {len(issues)} 个安全问题" if issues else ""
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO analyzed_commits (
                    commit_hash,
                    analyzed_at,
                    status,
                    security_related,
                    vulnerability_fix,
                    summary,
                    error,
                    subject,
                    author_name,
                    author_email,
                    authored_at,
                    parent_hashes,
                    patch_truncated,
                    original_code_truncated,
                    raw_result_json
                )
                VALUES (?, ?, 'analyzed', ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(commit_hash) DO UPDATE SET
                    analyzed_at = excluded.analyzed_at,
                    status = excluded.status,
                    security_related = excluded.security_related,
                    vulnerability_fix = excluded.vulnerability_fix,
                    summary = excluded.summary,
                    error = '',
                    subject = excluded.subject,
                    author_name = excluded.author_name,
                    author_email = excluded.author_email,
                    authored_at = excluded.authored_at,
                    parent_hashes = excluded.parent_hashes,
                    patch_truncated = excluded.patch_truncated,
                    original_code_truncated = excluded.original_code_truncated,
                    raw_result_json = excluded.raw_result_json
                """,
                (
                    info.commit_hash,
                    _utc_now(),
                    int(vulnerability_fix),
                    int(vulnerability_fix),
                    summary,
                    info.subject,
                    info.author_name,
                    info.author_email,
                    info.authored_at,
                    " ".join(info.parents),
                    int(payload.patch_truncated),
                    int(payload.original_code_truncated),
                    json.dumps({"issues": issues}, ensure_ascii=False, sort_keys=True),
                ),
            )
            self.connection.execute(
                "DELETE FROM vulnerabilities WHERE commit_hash = ?",
                (info.commit_hash,),
            )
            for issue_number, issue in enumerate(issues, start=1):
                self.connection.execute(
                    """
                    INSERT INTO vulnerabilities (
                        issue_number,
                        commit_hash,
                        description,
                        root_cause,
                        original_code,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        issue_number,
                        info.commit_hash,
                        issue["description"],
                        issue["root_cause"],
                        issue["original_code"],
                        _utc_now(),
                    ),
                )
        return len(issues)


class GitHistoryAnalyzer:
    """Analyze commits concurrently and persist confirmed vulnerability fixes."""

    def __init__(self, options: GitHistoryAnalysisOptions | None = None):
        self.options = options or GitHistoryAnalysisOptions()
        self.repo_path = self._resolve_repo_path(Path(self.options.repo_path))
        self.db_path = Path(self.options.db_path)
        self._validate_options()

    async def analyze(self) -> GitHistoryAnalysisSummary:
        commit_hashes = self._list_commit_hashes()
        store = _SQLiteResultStore(self.db_path)
        store.open()
        db_lock = asyncio.Lock()
        try:
            scheduled = [
                commit_hash
                for commit_hash in commit_hashes
                if not (
                    self.options.skip_analyzed
                    and store.has_completed_analysis(commit_hash)
                )
            ]
            summary = _SummaryBuilder(
                database_path=str(self.db_path),
                total_commits=len(commit_hashes),
                scheduled_commits=len(scheduled),
            )
            summary.skipped_commits = len(commit_hashes) - len(scheduled)
            semaphore = asyncio.Semaphore(self.options.concurrency)
            tasks = [
                asyncio.create_task(
                    self._analyze_commit(commit_hash, store, db_lock, semaphore)
                )
                for commit_hash in scheduled
            ]
            for task in asyncio.as_completed(tasks):
                summary.add_outcome(await task)
            return summary.build()
        finally:
            store.close()

    async def _analyze_commit(
        self,
        commit_hash: str,
        store: _SQLiteResultStore,
        db_lock: asyncio.Lock,
        semaphore: asyncio.Semaphore,
    ) -> _CommitOutcome:
        async with semaphore:
            info: _CommitInfo | None = None
            try:
                payload = self._load_commit_payload(commit_hash)
                info = payload.info
                if payload.skip_reason:
                    async with db_lock:
                        store.record_skipped(payload)
                    return _CommitOutcome(status="skipped")

                analysis = await self._run_agent_analysis(payload)
                issues = _normalize_issues(analysis.get("issues", []))
                async with db_lock:
                    saved = store.record_analysis(payload, issues)
                vulnerability_fix = bool(issues)
                return _CommitOutcome(
                    status="analyzed",
                    security_related=vulnerability_fix,
                    vulnerability_fix=vulnerability_fix,
                    vulnerabilities_saved=saved,
                )
            except Exception as exc:
                if info is None:
                    try:
                        info = self._get_commit_info(commit_hash)
                    except Exception:
                        info = None
                async with db_lock:
                    store.record_failure(info, commit_hash, f"{type(exc).__name__}: {exc}")
                return _CommitOutcome(status="failed")

    async def _run_agent_analysis(self, payload: _CommitPayload) -> dict[str, Any]:
        schema_text = json.dumps(ANALYSIS_RESULT_SCHEMA, ensure_ascii=False, indent=2)
        prompt = self._build_prompt(payload, schema_text)
        retry_prompt = (
            "上一次回复不是符合要求的 JSON。请只返回一个严格符合下方 JSON Schema 的 JSON 对象，"
            "不要输出 Markdown 或解释文字：\n"
            f"{schema_text}"
        )
        result = await run_opencode_task(
            task_name=f"git history analysis {payload.info.commit_hash[:12]}",
            task_type="git_history",
            prompt=prompt,
            required_capability=self.options.required_capability,
            output_schema=ANALYSIS_RESULT_SCHEMA,
            invalid_json_retry_count=2,
            invalid_json_retry_prompt=retry_prompt,
            session_id=None,
            config_path=self.options.config_path,
            output=self.options.output,
            cancel_event=self.options.cancel_event,
        )
        if getattr(result, "status", "") != "success":
            raise RuntimeError(f"agent task ended with status {getattr(result, 'status', '')!r}")
        structured = getattr(result, "structured", None)
        if not isinstance(structured, dict):
            raise TypeError("agent task did not return a structured JSON object")
        return structured

    def _build_prompt(self, payload: _CommitPayload, schema_text: str) -> str:
        info = payload.info
        body = info.body.strip() or "(empty)"
        patch_note = "yes" if payload.patch_truncated else "no"
        original_note = "yes" if payload.original_code_truncated else "no"
        return f"""\
你是网络安全代码审计 agent。你只能基于下面给出的 git commit 信息、diff 和父版本代码片段作出判断。

任务目标：
1. 判断该 commit 是否是在修复真实的网络安全问题。
2. 如果确认是在修复安全问题，把每个独立问题放入 `issues` 数组。
3. 每个问题只输出 `description`（问题描述）、`root_cause`（问题根因）和 `original_code`（修复前的原始问题代码）三个字段。问题编号由程序生成，不要输出编号或其它字段。

判定要求：
- 只有认证鉴权、访问控制、注入、XSS、SSRF、路径穿越、反序列化、RCE、内存安全、加密/随机数、敏感信息泄露、权限绕过、请求伪造、DoS 等真实安全问题才算网络安全相关。
- 不要把普通重构、测试变更、依赖整理、文档、日志、性能优化、泛泛的 bug fix 当成漏洞修复。
- `description` 要准确说明问题是什么、在什么场景下触发以及可能造成的安全影响，不能只写漏洞类型。
- `root_cause` 必须紧密结合 `original_code` 中的具体函数、变量和调用详细说明完整因果链：攻击者可控输入从哪里进入，经过哪些处理或传递，缺少哪项校验、鉴权或边界约束，最终在哪个危险操作处触发问题；还要结合 diff 说明本次改动为什么切断了这条问题链。不能只写“缺少校验”“存在注入”等泛泛结论。
- `original_code` 必须是修复前真正导致问题的原始代码，并包含理解根因所需的上下文。优先从 diff 删除行和父版本代码片段中还原，不允许贴修复后代码。
- 只有能同时确认问题、详细根因和原始问题代码时才输出该问题；否则 `issues` 输出空数组。
- 多个独立问题分别输出为多个 `issues` 元素，保持它们在 diff 中出现的顺序。
- 最终回复必须只包含一个严格符合 JSON Schema 的 JSON 对象，不要输出 Markdown 或解释文字。

Commit:
- hash: {info.commit_hash}
- parents: {" ".join(info.parents)}
- author: {info.author_name} <{info.author_email}>
- authored_at: {info.authored_at}
- subject: {info.subject}
- body:
{body}

父版本原始代码片段是否截断: {original_note}
```text
{payload.original_code or "(no parent-version source snippets were extracted)"}
```

Diff 是否截断: {patch_note}
```diff
{payload.patch}
```

JSON Schema:
{schema_text}
"""

    def _load_commit_payload(self, commit_hash: str) -> _CommitPayload:
        info = self._get_commit_info(commit_hash)
        if not info.parents:
            return _CommitPayload(info=info, skip_reason="root commit has no parent")
        if len(info.parents) > 1 and not self.options.include_merges:
            return _CommitPayload(info=info, skip_reason="merge commit skipped")

        parent = info.parents[0]
        patch = self._git(
            [
                "diff",
                "--find-renames",
                "--find-copies",
                "--no-ext-diff",
                "--no-color",
                f"--unified={self.options.diff_context_lines}",
                parent,
                commit_hash,
            ]
        )
        if not patch.strip():
            return _CommitPayload(info=info, skip_reason="empty diff")

        hunks = _parse_diff_hunks(patch)
        original_code = self._extract_original_code(parent, hunks)
        patch, patch_truncated = _truncate_text(patch, self.options.max_patch_chars)
        original_code, original_code_truncated = _truncate_text(
            original_code,
            self.options.max_original_code_chars,
        )
        return _CommitPayload(
            info=info,
            patch=patch,
            original_code=original_code,
            patch_truncated=patch_truncated,
            original_code_truncated=original_code_truncated,
        )

    def _extract_original_code(
        self,
        parent_hash: str,
        hunks: dict[str, list[tuple[int, int]]],
    ) -> str:
        sections: list[str] = []
        for file_path, ranges in hunks.items():
            if not file_path:
                continue
            content = self._git_show_file(parent_hash, file_path)
            if content is None:
                continue
            lines = content.splitlines()
            for old_start, old_count in ranges[: self.options.max_hunks_per_file]:
                if not lines:
                    continue
                context = max(0, min(self.options.diff_context_lines, 40))
                start = max(1, old_start - context)
                end = min(len(lines), old_start + max(old_count, 1) + context)
                snippet = "\n".join(
                    f"{line_no:>6}: {lines[line_no - 1]}"
                    for line_no in range(start, end + 1)
                )
                sections.append(
                    f"### {file_path}:{start}-{end}\n"
                    f"```text\n{snippet}\n```"
                )
        return "\n\n".join(sections)

    def _list_commit_hashes(self) -> list[str]:
        args = ["rev-list"]
        if self.options.max_commits is not None:
            args.append(f"--max-count={self.options.max_commits}")
        if self.options.since:
            args.append(f"--since={self.options.since}")
        if self.options.until:
            args.append(f"--until={self.options.until}")
        args.append(self.options.revision_range or "HEAD")
        commits = [line.strip() for line in self._git(args).splitlines() if line.strip()]
        commits.reverse()
        return commits

    def _get_commit_info(self, commit_hash: str) -> _CommitInfo:
        output = self._git(
            [
                "show",
                "-s",
                "--format=%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%s%x1f%b",
                commit_hash,
            ]
        )
        parts = output.split("\x1f", 6)
        if len(parts) != 7:
            raise ValueError(f"unable to parse commit metadata for {commit_hash}")
        return _CommitInfo(
            commit_hash=parts[0].strip(),
            parents=tuple(part for part in parts[1].split() if part),
            author_name=parts[2].strip(),
            author_email=parts[3].strip(),
            authored_at=parts[4].strip(),
            subject=parts[5].strip(),
            body=parts[6].strip(),
        )

    def _git_show_file(self, commit_hash: str, file_path: str) -> str | None:
        result = self._run_git(["show", f"{commit_hash}:{file_path}"], check=False)
        if result.returncode != 0:
            return None
        if "\x00" in result.stdout:
            return None
        return result.stdout

    def _git(self, args: list[str]) -> str:
        return self._run_git(args, check=True).stdout

    def _run_git(self, args: list[str], *, check: bool) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", *args],
            cwd=self.repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.options.git_timeout,
        )
        if check and result.returncode != 0:
            stderr = " ".join(result.stderr.split())
            raise RuntimeError(f"git {' '.join(args)} failed: {stderr}")
        return result

    def _resolve_repo_path(self, path: Path) -> Path:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.options.git_timeout,
        )
        if result.returncode != 0:
            stderr = " ".join(result.stderr.split())
            raise RuntimeError(f"{path} is not a git repository: {stderr}")
        return Path(result.stdout.strip()).resolve()

    def _validate_options(self) -> None:
        if self.options.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if self.options.max_commits is not None and self.options.max_commits < 1:
            raise ValueError("max_commits must be >= 1")
        if self.options.diff_context_lines < 0:
            raise ValueError("diff_context_lines must be >= 0")
        if self.options.max_patch_chars < 1:
            raise ValueError("max_patch_chars must be >= 1")
        if self.options.max_original_code_chars < 1:
            raise ValueError("max_original_code_chars must be >= 1")
        if self.options.max_hunks_per_file < 1:
            raise ValueError("max_hunks_per_file must be >= 1")
        if self.options.required_capability not in {"low", "high"}:
            raise ValueError("required_capability must be 'low' or 'high'")


async def analyze_git_history(
    options: GitHistoryAnalysisOptions | None = None,
    **overrides: Any,
) -> GitHistoryAnalysisSummary:
    """Analyze git commits and persist confirmed vulnerability fixes to SQLite."""
    if options is None:
        options = GitHistoryAnalysisOptions(**overrides)
    elif overrides:
        values = {**options.__dict__, **overrides}
        options = GitHistoryAnalysisOptions(**values)
    return await GitHistoryAnalyzer(options).analyze()


def _parse_diff_hunks(patch: str) -> dict[str, list[tuple[int, int]]]:
    hunks: dict[str, list[tuple[int, int]]] = {}
    old_path = ""
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            old_path = ""
            continue
        if line.startswith("--- "):
            old_path = _normalize_diff_path(line[4:])
            continue
        match = _HUNK_RE.match(line)
        if not match or not old_path:
            continue
        old_start = int(match.group("old_start"))
        old_count = int(match.group("old_count") or "1")
        hunks.setdefault(old_path, []).append((old_start, old_count))
    return hunks


def _normalize_diff_path(raw_path: str) -> str:
    value = raw_path.strip()
    if value == "/dev/null":
        return ""
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value


def _truncate_text(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    marker = "\n\n...[truncated]...\n\n"
    keep = max(1, (limit - len(marker)) // 2)
    return f"{text[:keep]}{marker}{text[-keep:]}", True


def _normalize_issues(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    issues: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        issue = {
            "description": _clean_text(item.get("description")),
            "root_cause": _clean_text(item.get("root_cause")),
            "original_code": _clean_text(item.get("original_code")),
        }
        if (
            issue["description"]
            and issue["root_cause"]
            and issue["original_code"]
        ):
            issues.append(issue)
    return issues


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
