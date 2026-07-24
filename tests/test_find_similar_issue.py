from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace

import find_similar_issue.analyzer as similar_module
from find_similar_issue import (
    FindSimilarIssueOptions,
    FindSimilarIssueResult,
    SimilarIssueFinding,
    find_similar_issue,
    run_similar_issues_audit,
)


class FindSimilarIssueTests(unittest.TestCase):
    def test_two_step_hunt_discovers_locations_then_audits_them(self) -> None:
        known_issue = {
            "description": "下载接口允许攻击者读取基础目录之外的文件。",
            "root_cause": (
                "download_file 将用户可控 path 与 base_dir 拼接后直接读取，"
                "没有规范化路径并检查目录边界。"
            ),
            "original_code": "return (base_dir / path).read_bytes()",
        }
        candidates = [
            {"code_location": "api/export.py:40-42"},
            {"code_location": "api/import.py:8,12-15,19"},
        ]
        calls: list[dict[str, object]] = []
        active_validations = 0
        max_active_validations = 0

        async def fake_run_opencode_task(**kwargs: object) -> object:
            nonlocal active_validations, max_active_validations
            calls.append(kwargs)
            self.assertEqual(kwargs["task_type"], "variant_hunt")
            self.assertEqual(kwargs["required_capability"], "high")
            self.assertIn("run_opencode_task", similar_module.__dict__)

            task_name = str(kwargs["task_name"])
            if task_name == "similar issue candidate discovery":
                prompt = str(kwargs["prompt"])
                self.assertIn("历史漏洞描述", prompt)
                self.assertIn(known_issue["description"], prompt)
                self.assertIn("历史漏洞根因", prompt)
                self.assertIn(known_issue["root_cause"], prompt)
                self.assertIn("历史漏洞代码", prompt)
                self.assertIn(known_issue["original_code"], prompt)
                self.assertIn("不负责确认候选是否真实存在漏洞", prompt)
                self.assertIn("允许误报", prompt)
                self.assertIn("path/to/file.py:42-57", prompt)
                self.assertIn("path/to/file.py:42,48-53,61", prompt)
                schema = kwargs["output_schema"]
                item_schema = schema["properties"]["candidates"]["items"]
                self.assertEqual(
                    set(item_schema["properties"]),
                    {"code_location"},
                )
                return SimpleNamespace(
                    status="success",
                    structured={"candidates": candidates},
                )

            active_validations += 1
            max_active_validations = max(max_active_validations, active_validations)
            try:
                await asyncio.sleep(0.01)
            finally:
                active_validations -= 1

            code_location = (
                "api/export.py:40-42"
                if "api/export.py" in task_name
                else "api/import.py:8,12-15,19"
            )
            prompt = str(kwargs["prompt"])
            self.assertIn(known_issue["description"], prompt)
            self.assertIn(known_issue["root_cause"], prompt)
            self.assertIn(known_issue["original_code"], prompt)
            self.assertIn(code_location, prompt)
            exists = code_location == "api/export.py:40-42"
            return SimpleNamespace(
                status="success",
                structured={
                    "code_location": code_location,
                    "similar_issue_exists": exists,
                    "severity": "high" if exists else "none",
                    "title": "导出路径穿越" if exists else "",
                    "root_cause": (
                        "用户可控 filename 直接参与路径拼接。"
                        if exists
                        else ""
                    ),
                    "evidence": (
                        "api/export.py:40-42 将 filename 拼接后读取。"
                        if exists
                        else "api/import.py:8,12-15,19 已执行目录边界检查。"
                    ),
                    "attack_path": "HTTP filename 参数到文件读取。" if exists else "",
                    "similarity_analysis": (
                        "输入、危险操作和缺失边界检查均相似。"
                        if exists
                        else ""
                    ),
                    "difference_analysis": "" if exists else "存在有效边界检查。",
                    "recommendation": "规范化路径并检查目录边界。" if exists else "",
                    "confidence": "high",
                },
            )

        original_runner = similar_module.run_opencode_task
        similar_module.run_opencode_task = fake_run_opencode_task
        try:
            result = asyncio.run(
                find_similar_issue(
                    FindSimilarIssueOptions(
                        known_issue=known_issue,
                        concurrency=2,
                    )
                )
            )
        finally:
            similar_module.run_opencode_task = original_runner

        self.assertEqual(len(calls), 3)
        self.assertEqual(
            [candidate.code_location for candidate in result.candidates],
            ["api/export.py:40-42", "api/import.py:8,12-15,19"],
        )
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.findings[0].code_location, "api/export.py:40-42")
        self.assertTrue(result.findings[0].similar_issue_exists)
        self.assertEqual(result.findings[1].severity, "none")
        self.assertEqual(max_active_validations, 2)
        self.assertEqual(
            set(result.to_dict()),
            {"candidates", "findings"},
        )

    def test_empty_candidate_list_skips_validation_step(self) -> None:
        calls: list[dict[str, object]] = []

        async def fake_run_opencode_task(**kwargs: object) -> object:
            calls.append(kwargs)
            self.assertEqual(
                kwargs["task_name"],
                "similar issue candidate discovery",
            )
            self.assertIn("已知 SQL 注入问题", str(kwargs["prompt"]))
            return SimpleNamespace(
                status="success",
                structured={"candidates": []},
            )

        original_runner = similar_module.run_opencode_task
        similar_module.run_opencode_task = fake_run_opencode_task
        try:
            result = asyncio.run(find_similar_issue("已知 SQL 注入问题"))
        finally:
            similar_module.run_opencode_task = original_runner

        self.assertEqual(len(calls), 1)
        self.assertEqual(result.candidates, [])
        self.assertEqual(result.findings, [])

    def test_candidate_locations_are_normalized_deduplicated_and_limited(self) -> None:
        candidates = similar_module._normalize_candidates(
            [
                {"code_location": " src/a.py:12 "},
                {"code_location": "src/a.py:12"},
                {"code_location": "src/b.py:20 - 25, 31,31"},
                {"code_location": "src/c.py:0"},
                {"code_location": "src/d.py:30-20"},
                {"code_location": "src/e.py:not-a-line"},
                {"code_location": "src/f.py:50,52-54"},
            ],
            max_candidates=3,
        )

        self.assertEqual(
            [candidate.code_location for candidate in candidates],
            [
                "src/a.py:12",
                "src/b.py:20-25,31",
                "src/f.py:50,52-54",
            ],
        )

    def test_run_similar_issues_audit_returns_only_confirmed_findings(self) -> None:
        received: dict[str, object] = {}
        confirmed = SimilarIssueFinding(
            code_location="src/export.py:20-24",
            similar_issue_exists=True,
            severity="high",
            title="导出路径穿越",
            root_cause="用户输入未经边界检查直接进入文件读取。",
            evidence="src/export.py:20-24",
            attack_path="HTTP 参数到文件读取。",
            similarity_analysis="与历史漏洞根因一致。",
            difference_analysis="使用了不同的文件读取 API。",
            recommendation="规范化路径并验证目录边界。",
            confidence="high",
        )
        rejected = SimilarIssueFinding(
            code_location="src/safe_export.py:30,35-39",
            similar_issue_exists=False,
            severity="none",
            title="",
            root_cause="",
            evidence="存在有效目录边界检查。",
            attack_path="",
            similarity_analysis="",
            difference_analysis="候选已实施有效安全控制。",
            recommendation="",
            confidence="high",
        )

        async def fake_find_similar_issue(
            known_issue: object,
            **overrides: object,
        ) -> FindSimilarIssueResult:
            received["known_issue"] = known_issue
            received["overrides"] = overrides
            return FindSimilarIssueResult(
                candidates=[],
                findings=[confirmed, rejected],
            )

        original_find = similar_module.find_similar_issue
        similar_module.find_similar_issue = fake_find_similar_issue
        try:
            findings = asyncio.run(
                run_similar_issues_audit(
                    "下载接口可读取目录外文件。",
                    "用户路径未经规范化和目录边界检查。",
                    "return (base_dir / path).read_bytes()",
                    "src/export",
                )
            )
        finally:
            similar_module.find_similar_issue = original_find

        self.assertEqual(
            received["known_issue"],
            {
                "description": "下载接口可读取目录外文件。",
                "root_cause": "用户路径未经规范化和目录边界检查。",
                "original_code": "return (base_dir / path).read_bytes()",
            },
        )
        self.assertIn(
            "src/export",
            str(received["overrides"]),
        )
        self.assertEqual(findings, [confirmed.to_dict()])
        self.assertEqual(
            set(findings[0]),
            {
                "code_location",
                "similar_issue_exists",
                "severity",
                "title",
                "root_cause",
                "evidence",
                "attack_path",
                "similarity_analysis",
                "difference_analysis",
                "recommendation",
                "confidence",
            },
        )

    def test_run_similar_issues_audit_rejects_empty_inputs(self) -> None:
        with self.assertRaisesRegex(ValueError, "issue_description"):
            asyncio.run(
                run_similar_issues_audit(
                    "",
                    "漏洞根因",
                    "漏洞代码",
                    "src",
                )
            )


if __name__ == "__main__":
    unittest.main()
