from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

from web_dashboard import DashboardStore, create_dashboard_server


def _create_result_database(db_path: Path) -> None:
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE analyzed_commits (
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

            CREATE TABLE vulnerabilities (
                issue_number INTEGER NOT NULL,
                commit_hash TEXT NOT NULL,
                description TEXT NOT NULL,
                root_cause TEXT NOT NULL,
                original_code TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (commit_hash, issue_number)
            );

            CREATE TABLE similar_issue_audits (
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

            CREATE TABLE similar_issue_findings (
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
            """
        )
        commits = [
            (
                "a" * 40,
                "2026-07-24T08:00:00+00:00",
                "analyzed",
                1,
                1,
                "确认修复 1 个安全问题",
                "",
                "fix path traversal",
                "Alice",
                "alice@example.com",
                "2026-07-20T08:00:00+00:00",
            ),
            (
                "b" * 40,
                "2026-07-24T08:01:00+00:00",
                "failed",
                0,
                0,
                "",
                "model unavailable",
                "refactor exporter",
                "Bob",
                "bob@example.com",
                "2026-07-21T08:00:00+00:00",
            ),
        ]
        connection.executemany(
            """
            INSERT INTO analyzed_commits (
                commit_hash, analyzed_at, status, security_related,
                vulnerability_fix, summary, error, subject, author_name,
                author_email, authored_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            commits,
        )
        connection.executemany(
            """
            INSERT INTO vulnerabilities (
                issue_number, commit_hash, description, root_cause,
                original_code, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1,
                    "a" * 40,
                    "导出接口存在路径穿越",
                    "用户路径未经目录边界检查",
                    "return (base / filename).read_text()",
                    "2026-07-24T08:02:00+00:00",
                ),
                (
                    2,
                    "a" * 40,
                    "用户查询存在 SQL 注入",
                    "SQL 使用字符串拼接",
                    "db.execute(f'SELECT {user_id}')",
                    "2026-07-24T08:03:00+00:00",
                ),
            ],
        )
        connection.executemany(
            """
            INSERT INTO similar_issue_audits (
                source_commit_hash, source_issue_number, code_path,
                status, updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("a" * 40, 1, "/code/project", "running", "2026-07-24"),
                ("a" * 40, 2, "/code/project", "completed", "2026-07-24"),
                ("a" * 40, 3, "/code/project", "failed", "2026-07-24"),
            ],
        )
        findings = [
            (
                "a" * 40,
                1,
                "/code/project",
                1,
                "HEAD",
                "src/export.py:40-42",
                1,
                "high",
                "导出路径穿越",
                "filename 未验证",
                "拼接后直接读取",
                "HTTP 参数到文件读取",
                "根因一致",
                "使用了不同文件 API",
                "规范化并检查目录边界",
                "high",
                "2026-07-24T08:04:00+00:00",
                "{}",
            ),
            (
                "a" * 40,
                2,
                "/code/project",
                1,
                "HEAD",
                "src/users.py:20",
                1,
                "medium",
                "用户查询 SQL 注入",
                "查询参数被拼接",
                "直接执行拼接 SQL",
                "HTTP 参数到数据库",
                "危险操作一致",
                "",
                "使用参数绑定",
                "medium",
                "2026-07-24T08:05:00+00:00",
                "{}",
            ),
        ]
        connection.executemany(
            """
            INSERT INTO similar_issue_findings (
                source_commit_hash, source_issue_number, code_path,
                finding_number, target_revision, code_location,
                similar_issue_exists, severity, title, root_cause, evidence,
                attack_path, similarity_analysis, difference_analysis,
                recommendation, confidence, created_at, raw_result_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            findings,
        )
        connection.commit()
    finally:
        connection.close()


class DashboardStoreTests(unittest.TestCase):
    def test_summary_and_paginated_tables_reflect_database_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "mirrorsec.sqlite3"
            _create_result_database(db_path)
            store = DashboardStore(db_path)

            summary = store.summary()
            self.assertTrue(summary["database"]["exists"])
            self.assertEqual(summary["history"]["issues"], 2)
            self.assertEqual(summary["history"]["commits"], 2)
            self.assertEqual(summary["history"]["fix_commits"], 1)
            self.assertEqual(summary["history"]["failed"], 1)
            self.assertEqual(summary["findings"]["total"], 2)
            self.assertEqual(summary["findings"]["high"], 1)
            self.assertEqual(summary["findings"]["running"], 1)
            self.assertEqual(summary["findings"]["completed"], 1)
            self.assertEqual(summary["findings"]["failed"], 1)

            history = store.history_issues(query="路径", page=1, page_size=10)
            self.assertEqual(history["total"], 1)
            self.assertEqual(history["items"][0]["issue_id"], f"{'a' * 12}#1")
            self.assertEqual(history["items"][0]["author_name"], "Alice")

            findings = store.similar_findings(
                query="export.py",
                severity="high",
                page=1,
                page_size=10,
            )
            self.assertEqual(findings["total"], 1)
            self.assertEqual(findings["items"][0]["title"], "导出路径穿越")
            self.assertEqual(
                findings["items"][0]["source_description"],
                "导出接口存在路径穿越",
            )

    def test_missing_database_returns_an_empty_waiting_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "not-created-yet.sqlite3"
            store = DashboardStore(db_path)

            self.assertFalse(store.summary()["database"]["exists"])
            self.assertEqual(store.history_issues()["items"], [])
            self.assertEqual(store.similar_findings()["total"], 0)
            self.assertFalse(db_path.exists())


class DashboardHTTPTests(unittest.TestCase):
    def test_loading_overlay_honors_hidden_attribute(self) -> None:
        stylesheet = (
            Path(__file__).resolve().parents[1] / "web" / "styles.css"
        ).read_text(encoding="utf-8")

        self.assertIn(
            ".loading-overlay[hidden] {\n  display: none;\n}",
            stylesheet,
        )

    def test_static_frontend_and_json_api_are_served(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "mirrorsec.sqlite3"
            _create_result_database(db_path)
            dashboard = create_dashboard_server(db_path, port=0).start()
            opener = build_opener(ProxyHandler({}))
            try:
                with opener.open(f"{dashboard.url}/", timeout=3) as response:
                    html = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertIn("Git 历史问题", html)
                    self.assertIn("问题排查结果", html)
                    self.assertIn("立即刷新", html)

                with opener.open(
                    f"{dashboard.url}/app.js",
                    timeout=3,
                ) as response:
                    javascript = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertNotIn("setInterval", javascript)
                    self.assertNotIn('"visibilitychange"', javascript)
                    self.assertIn(
                        'elements.refreshButton.addEventListener("click"',
                        javascript,
                    )

                with opener.open(
                    f"{dashboard.url}/api/summary",
                    timeout=3,
                ) as response:
                    payload = json.loads(response.read())
                    self.assertEqual(response.status, 200)
                    self.assertEqual(payload["history"]["issues"], 2)

                writer = sqlite3.connect(db_path)
                try:
                    writer.execute(
                        """
                        INSERT INTO vulnerabilities (
                            issue_number, commit_hash, description, root_cause,
                            original_code, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            3,
                            "a" * 40,
                            "任务运行中新增的问题",
                            "新写入的根因",
                            "new_vulnerable_call()",
                            "2026-07-24T08:06:00+00:00",
                        ),
                    )
                    writer.commit()
                finally:
                    writer.close()

                with opener.open(
                    f"{dashboard.url}/api/history?page_size=10",
                    timeout=3,
                ) as response:
                    payload = json.loads(response.read())
                    self.assertEqual(payload["total"], 3)
                    self.assertEqual(
                        payload["items"][0]["description"],
                        "任务运行中新增的问题",
                    )

                with opener.open(
                    f"{dashboard.url}/api/findings?severity=high&page_size=1",
                    timeout=3,
                ) as response:
                    payload = json.loads(response.read())
                    self.assertEqual(payload["total"], 1)
                    self.assertEqual(payload["items"][0]["severity"], "high")
            finally:
                dashboard.close()


if __name__ == "__main__":
    unittest.main()
