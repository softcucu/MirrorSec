from __future__ import annotations

import asyncio
import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import git_history_analysis.analyzer as analyzer_module
from git_history_analysis import GitHistoryAnalysisOptions, analyze_git_history


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", ".")
    _git(
        repo,
        "-c",
        "user.name=Tester",
        "-c",
        "user.email=tester@example.com",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--no-verify",
        "-m",
        message,
    )


class GitHistoryAnalysisTests(unittest.TestCase):
    def test_commit_stream_keeps_only_concurrency_sized_work_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            _git(repo, "init", "-q")

            source = repo / "app.py"
            source.write_text("value = 1\n", encoding="utf-8")
            _commit(repo, "initial commit")

            analyzer = analyzer_module.GitHistoryAnalyzer(
                GitHistoryAnalysisOptions(
                    repo_path=repo,
                    db_path=root / "history.sqlite3",
                    concurrency=3,
                )
            )
            produced = 0
            completed = 0
            max_buffered = 0
            active = 0
            max_active = 0

            async def fake_commit_stream():
                nonlocal produced, max_buffered
                for index in range(100):
                    produced += 1
                    max_buffered = max(max_buffered, produced - completed)
                    yield f"{index:040x}"

            async def fake_analyze_commit(
                commit_hash: str,
                store: object,
                db_lock: object,
            ) -> object:
                del commit_hash, store, db_lock
                nonlocal active, completed, max_active
                active += 1
                max_active = max(max_active, active)
                await asyncio.sleep(0)
                active -= 1
                completed += 1
                return analyzer_module._CommitOutcome(status="analyzed")

            analyzer._iter_commit_hashes = fake_commit_stream
            analyzer._analyze_commit = fake_analyze_commit
            summary = asyncio.run(analyzer.analyze())

            self.assertEqual(summary.total_commits, 100)
            self.assertEqual(summary.scheduled_commits, 100)
            self.assertEqual(summary.analyzed_commits, 100)
            self.assertLessEqual(max_active, 3)
            self.assertLessEqual(max_buffered, 3)

    def test_confirmed_vulnerability_fix_is_saved_to_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            db_path = root / "history.sqlite3"
            _git(repo, "init", "-q")

            source = repo / "app.py"
            source.write_text(
                "def get_user(db, user_id):\n"
                "    sql = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
                "    return db.execute(sql)\n"
                "\n"
                "def read_export(base_dir, filename):\n"
                "    return (base_dir / filename).read_text()\n",
                encoding="utf-8",
            )
            _commit(repo, "add vulnerable lookup")

            source.write_text(
                "def get_user(db, user_id):\n"
                "    return db.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n"
                "\n"
                "def read_export(base_dir, filename):\n"
                "    path = (base_dir / filename).resolve()\n"
                "    if base_dir.resolve() not in path.parents:\n"
                "        raise ValueError(\"invalid export path\")\n"
                "    return path.read_text()\n",
                encoding="utf-8",
            )
            _commit(repo, "fix sql injection in user lookup")

            calls: list[dict[str, object]] = []

            async def fake_run_opencode_task(**kwargs: object) -> object:
                calls.append(kwargs)
                self.assertEqual(kwargs["task_type"], "git_history")
                self.assertEqual(kwargs["required_capability"], "high")
                self.assertIn("run_opencode_task", analyzer_module.__dict__)
                prompt = str(kwargs["prompt"])
                self.assertIn("修复前", prompt)
                self.assertIn("完整因果链", prompt)
                self.assertIn("git show --stat --summary", prompt)
                self.assertIn("git diff --unified=8", prompt)
                self.assertIn("git diff-tree", prompt)
                self.assertNotIn("SELECT * FROM users", prompt)
                self.assertNotIn("read_export(base_dir, filename)", prompt)
                self.assertLess(len(prompt), 10_000)
                schema = kwargs["output_schema"]
                self.assertEqual(set(schema["properties"]), {"issues"})
                issue_schema = schema["properties"]["issues"]["items"]
                self.assertEqual(
                    set(issue_schema["properties"]),
                    {"description", "root_cause", "original_code"},
                )
                return SimpleNamespace(
                    status="success",
                    structured={
                        "issues": [
                            {
                                "description": (
                                    "用户查询接口允许外部输入改变 SQL 语义，"
                                    "可导致未授权数据查询。"
                                ),
                                "root_cause": (
                                    "get_user 将攻击者可控的 user_id 直接拼接进 SQL，"
                                    "原始代码中的 f-string 没有参数化绑定，随后将拼接结果"
                                    "传给 db.execute 执行；改为占位符绑定后，user_id 不再被"
                                    "数据库解释为 SQL 语法。"
                                ),
                                "original_code": (
                                    "sql = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
                                    "return db.execute(sql)"
                                ),
                            },
                            {
                                "description": (
                                    "导出文件读取接口存在路径穿越，攻击者可读取导出目录外文件。"
                                ),
                                "root_cause": (
                                    "read_export 直接用攻击者可控的 filename 与 base_dir 拼接，"
                                    "未规范化路径也未验证最终路径仍位于 base_dir 内，随后立即"
                                    "调用 read_text 读取；修复代码先 resolve 并检查父目录，"
                                    "从而阻止 ../ 逃逸。"
                                ),
                                "original_code": (
                                    "def read_export(base_dir, filename):\n"
                                    "    return (base_dir / filename).read_text()"
                                ),
                            }
                        ],
                    },
                )

            original_runner = analyzer_module.run_opencode_task
            analyzer_module.run_opencode_task = fake_run_opencode_task
            try:
                summary = asyncio.run(
                    analyze_git_history(
                        GitHistoryAnalysisOptions(
                            repo_path=repo,
                            db_path=db_path,
                            revision_range="HEAD",
                            max_commits=1,
                            concurrency=2,
                        )
                    )
                )
            finally:
                analyzer_module.run_opencode_task = original_runner

            self.assertEqual(len(calls), 1)
            self.assertEqual(summary.analyzed_commits, 1)
            self.assertEqual(summary.vulnerability_fix_commits, 1)
            self.assertEqual(summary.vulnerabilities_saved, 2)

            connection = sqlite3.connect(db_path)
            try:
                rows = connection.execute(
                    """
                    SELECT issue_number, description, root_cause, original_code
                    FROM vulnerabilities
                    ORDER BY issue_number
                    """
                ).fetchall()
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(vulnerabilities)"
                    ).fetchall()
                }
                raw_result = connection.execute(
                    "SELECT raw_result_json FROM analyzed_commits"
                ).fetchone()[0]
                truncation_flags = connection.execute(
                    """
                    SELECT patch_truncated, original_code_truncated
                    FROM analyzed_commits
                    """
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual([row[0] for row in rows], [1, 2])
            self.assertIn("SQL", rows[0][1])
            self.assertIn("user_id", rows[0][2])
            self.assertIn("SELECT * FROM users", rows[0][3])
            self.assertIn("路径穿越", rows[1][1])
            self.assertEqual(
                columns,
                {
                    "issue_number",
                    "commit_hash",
                    "description",
                    "root_cause",
                    "original_code",
                    "created_at",
                },
            )
            self.assertEqual(
                set(json.loads(raw_result)),
                {"issues"},
            )
            self.assertEqual(truncation_flags, (0, 0))

    def test_commit_message_is_bounded_in_lightweight_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            _git(repo, "init", "-q")

            source = repo / "app.py"
            source.write_text("value = 1\n", encoding="utf-8")
            _commit(repo, "initial commit")
            source.write_text("value = 2\n", encoding="utf-8")
            long_body = "untrusted metadata " * 1_000
            _git(repo, "add", ".")
            _git(
                repo,
                "-c",
                "user.name=Tester",
                "-c",
                "user.email=tester@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--no-verify",
                "-m",
                "update value",
                "-m",
                long_body,
            )

            analyzer = analyzer_module.GitHistoryAnalyzer(
                GitHistoryAnalysisOptions(
                    repo_path=repo,
                    db_path=root / "history.sqlite3",
                )
            )
            commit_hash = analyzer._git(["rev-parse", "HEAD"]).strip()
            payload = analyzer._load_commit_payload(commit_hash)
            schema_text = json.dumps(
                analyzer_module.ANALYSIS_RESULT_SCHEMA,
                ensure_ascii=False,
                indent=2,
            )
            prompt = analyzer._build_prompt(payload, schema_text)

            self.assertIn("[commit metadata truncated]", prompt)
            self.assertNotIn(long_body, prompt)
            self.assertLess(len(prompt), 10_000)


if __name__ == "__main__":
    unittest.main()
