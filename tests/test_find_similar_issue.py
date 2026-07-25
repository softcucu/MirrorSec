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
    def test_two_step_hunt_generates_prompt_then_directly_audits(self) -> None:
        known_issue = {
            "description": "下载接口允许攻击者读取基础目录之外的文件。",
            "root_cause": (
                "download_file 将用户可控 path 与 base_dir 拼接后直接读取，"
                "没有规范化路径并检查目录边界。"
            ),
            "original_code": "return (base_dir / path).read_bytes()",
        }
        investigation_prompt = (
            "检索用户可控路径进入文件读取的位置；确认规范化后的路径是否"
            "被可靠限制在预期基础目录内，并验证攻击路径是否可达。"
        )
        calls: list[dict[str, object]] = []

        async def fake_run_opencode_task(**kwargs: object) -> object:
            calls.append(kwargs)
            self.assertEqual(kwargs["task_type"], "variant_hunt")
            self.assertEqual(kwargs["required_capability"], "high")
            self.assertIn("run_opencode_task", similar_module.__dict__)

            task_name = str(kwargs["task_name"])
            if task_name == "similar issue method generation":
                prompt = str(kwargs["prompt"])
                self.assertIn("历史问题描述", prompt)
                self.assertIn(known_issue["description"], prompt)
                self.assertIn("历史问题根因分析", prompt)
                self.assertIn(known_issue["root_cause"], prompt)
                self.assertIn("历史问题代码", prompt)
                self.assertIn(known_issue["original_code"], prompt)
                self.assertIn("一个完整、自包含、可执行", prompt)
                self.assertEqual(
                    set(kwargs["output_schema"]["properties"]),
                    {"investigation_prompt"},
                )
                return SimpleNamespace(
                    status="success",
                    structured={"investigation_prompt": investigation_prompt},
                )

            self.assertEqual(task_name, "similar issues audit")
            prompt = str(kwargs["prompt"])
            self.assertIn("审计提示词", prompt)
            self.assertIn(investigation_prompt, prompt)
            self.assertNotIn(known_issue["description"], prompt)
            self.assertNotIn(known_issue["original_code"], prompt)
            self.assertIn("直接完成同类问题排查", prompt)
            self.assertIn("不要输出中间疑似位置", prompt)
            schema = kwargs["output_schema"]
            finding_schema = schema["properties"]["findings"]["items"]
            self.assertEqual(
                set(finding_schema["properties"]),
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
            return SimpleNamespace(
                status="success",
                structured={
                    "findings": [
                        {
                            "code_location": "api/export.py:40-42",
                            "similar_issue_exists": True,
                            "severity": "high",
                            "title": "导出路径穿越",
                            "root_cause": "用户可控 filename 直接参与路径拼接。",
                            "evidence": "api/export.py:40-42 将 filename 拼接后读取。",
                            "attack_path": "HTTP filename 参数到文件读取。",
                            "similarity_analysis": "输入、危险操作和缺失边界检查均相似。",
                            "difference_analysis": "使用不同的文件读取 API。",
                            "recommendation": "规范化路径并检查目录边界。",
                            "confidence": "high",
                        },
                        {
                            "code_location": "api/archive.py:8,12-15,19",
                            "similar_issue_exists": True,
                            "severity": "medium",
                            "title": "归档路径穿越",
                            "root_cause": "归档条目路径未经目录边界检查。",
                            "evidence": "api/archive.py:8,12-15,19 写入任意条目路径。",
                            "attack_path": "上传归档文件到文件写入。",
                            "similarity_analysis": "缺失的目录边界约束相同。",
                            "difference_analysis": "危险操作是文件写入。",
                            "recommendation": "校验归档条目的规范化目标路径。",
                            "confidence": "high",
                        },
                    ]
                },
            )

        original_runner = similar_module.run_opencode_task
        similar_module.run_opencode_task = fake_run_opencode_task
        try:
            result = asyncio.run(
                find_similar_issue(
                    FindSimilarIssueOptions(known_issue=known_issue)
                )
            )
        finally:
            similar_module.run_opencode_task = original_runner

        self.assertEqual(len(calls), 2)
        self.assertEqual(
            [call["task_name"] for call in calls],
            ["similar issue method generation", "similar issues audit"],
        )
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.findings[0].code_location, "api/export.py:40-42")
        self.assertTrue(result.findings[0].similar_issue_exists)
        self.assertEqual(result.findings[1].severity, "medium")
        self.assertEqual(
            set(result.to_dict()),
            {"findings"},
        )

    def test_direct_audit_can_return_no_findings(self) -> None:
        calls: list[dict[str, object]] = []

        async def fake_run_opencode_task(**kwargs: object) -> object:
            calls.append(kwargs)
            if kwargs["task_name"] == "similar issue method generation":
                self.assertIn("已知 SQL 注入问题", str(kwargs["prompt"]))
                return SimpleNamespace(
                    status="success",
                    structured={
                        "investigation_prompt": "排查输入进入 SQL 执行且未参数化的位置。"
                    },
                )
            self.assertEqual(
                kwargs["task_name"],
                "similar issues audit",
            )
            self.assertIn(
                "排查输入进入 SQL 执行且未参数化的位置。",
                str(kwargs["prompt"]),
            )
            return SimpleNamespace(
                status="success",
                structured={"findings": []},
            )

        original_runner = similar_module.run_opencode_task
        similar_module.run_opencode_task = fake_run_opencode_task
        try:
            result = asyncio.run(find_similar_issue("已知 SQL 注入问题"))
        finally:
            similar_module.run_opencode_task = original_runner

        self.assertEqual(len(calls), 2)
        self.assertEqual(result.findings, [])

    def test_generated_investigation_prompt_must_not_be_empty(self) -> None:
        with self.assertRaisesRegex(ValueError, "investigation_prompt"):
            similar_module._normalize_investigation_prompt(
                {"investigation_prompt": " "}
            )

    def test_direct_findings_are_filtered_normalized_and_deduplicated(self) -> None:
        base_finding = {
            "similar_issue_exists": True,
            "severity": "high",
            "title": "路径穿越",
            "root_cause": "缺少目录边界检查。",
            "evidence": "具体代码证据。",
            "attack_path": "外部输入到文件读取。",
            "similarity_analysis": "根因相同。",
            "difference_analysis": "",
            "recommendation": "增加边界检查。",
            "confidence": "high",
        }
        findings = similar_module._normalize_findings(
            [
                {**base_finding, "code_location": " src/a.py:12 "},
                {**base_finding, "code_location": "src/a.py:12"},
                {
                    **base_finding,
                    "code_location": "src/safe.py:20",
                    "similar_issue_exists": False,
                },
                {**base_finding, "code_location": "src/c.py:0"},
                {**base_finding, "code_location": "src/d.py:30-20"},
                {**base_finding, "code_location": "src/f.py:50,52-54"},
            ]
        )

        self.assertEqual(
            [finding.code_location for finding in findings],
            [
                "src/a.py:12",
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
            difference_analysis="该位置已实施有效安全控制。",
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
