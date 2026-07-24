"""Two-step similar issue hunting backed by run_opencode_task only."""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Literal

from task_agent import run_opencode_task


CandidateConfidence = Literal["high", "medium", "low"]
FindingSeverity = Literal["critical", "high", "medium", "low", "none"]


CANDIDATE_DISCOVERY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "code_location": {
                        "type": "string",
                        "description": (
                            "当前仓库中的相对文件路径和关键代码行。支持单行、"
                            "连续范围或多个行号/范围，例如 "
                            "src/api.py:42、src/api.py:42-57、"
                            "src/api.py:42,48-53,61。"
                        ),
                        "minLength": 3,
                    },
                },
                "required": ["code_location"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["candidates"],
    "additionalProperties": False,
}


SIMILAR_ISSUE_VALIDATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "code_location": {"type": "string"},
        "similar_issue_exists": {"type": "boolean"},
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "none"],
        },
        "title": {"type": "string"},
        "root_cause": {"type": "string"},
        "evidence": {"type": "string"},
        "attack_path": {"type": "string"},
        "similarity_analysis": {"type": "string"},
        "difference_analysis": {"type": "string"},
        "recommendation": {"type": "string"},
        "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
        },
    },
    "required": [
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
    ],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class SimilarIssueCandidate:
    """One candidate location that may resemble the known issue."""

    code_location: str

    def to_dict(self) -> dict[str, Any]:
        return {"code_location": self.code_location}


@dataclass(frozen=True)
class SimilarIssueFinding:
    """Validation result for one candidate."""

    code_location: str
    similar_issue_exists: bool
    severity: FindingSeverity
    title: str
    root_cause: str
    evidence: str
    attack_path: str
    similarity_analysis: str
    difference_analysis: str
    recommendation: str
    confidence: CandidateConfidence = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code_location": self.code_location,
            "similar_issue_exists": self.similar_issue_exists,
            "severity": self.severity,
            "title": self.title,
            "root_cause": self.root_cause,
            "evidence": self.evidence,
            "attack_path": self.attack_path,
            "similarity_analysis": self.similarity_analysis,
            "difference_analysis": self.difference_analysis,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class FindSimilarIssueOptions:
    """Options for one similar issue hunt."""

    known_issue: str | dict[str, Any]
    search_scope: str = "当前工作区代码仓库"
    max_candidates: int | None = None
    concurrency: int = 4
    required_capability: Literal["low", "high"] = "high"
    config_path: str | os.PathLike[str] | None = None
    output: Callable[[str], Any] | None = None
    cancel_event: Any = None


@dataclass(frozen=True)
class FindSimilarIssueResult:
    """Combined candidates and validation findings."""

    candidates: list[SimilarIssueCandidate]
    findings: list[SimilarIssueFinding]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "findings": [finding.to_dict() for finding in self.findings],
        }


class FindSimilarIssueRunner:
    """Run candidate discovery followed by per-candidate validation."""

    def __init__(self, options: FindSimilarIssueOptions):
        self.options = options
        self.known_issue = _normalize_known_issue(options.known_issue)
        self.known_issue_text = _format_known_issue(self.known_issue)
        self._validate_options()

    async def run(self) -> FindSimilarIssueResult:
        candidates = await self._discover_candidates()
        if not candidates:
            return FindSimilarIssueResult(
                candidates=[],
                findings=[],
            )

        semaphore = asyncio.Semaphore(self.options.concurrency)
        findings = await asyncio.gather(
            *(
                self._validate_candidate_with_semaphore(
                    candidate,
                    semaphore,
                )
                for candidate in candidates
            )
        )
        return FindSimilarIssueResult(
            candidates=candidates,
            findings=list(findings),
        )

    async def _discover_candidates(self) -> list[SimilarIssueCandidate]:
        schema_text = json.dumps(
            CANDIDATE_DISCOVERY_SCHEMA,
            ensure_ascii=False,
            indent=2,
        )
        prompt = self._build_candidate_prompt(schema_text)
        result = await run_opencode_task(
            task_name="similar issue candidate discovery",
            task_type="variant_hunt",
            prompt=prompt,
            required_capability=self.options.required_capability,
            output_schema=CANDIDATE_DISCOVERY_SCHEMA,
            session_id=None,
            config_path=self.options.config_path,
            output=self.options.output,
            cancel_event=self.options.cancel_event,
        )
        if getattr(result, "status", "") != "success":
            raise RuntimeError(
                f"candidate discovery ended with status {getattr(result, 'status', '')!r}"
            )
        structured = getattr(result, "structured", None)
        if not isinstance(structured, dict):
            raise TypeError("candidate discovery did not return a JSON object")
        return _normalize_candidates(
            structured.get("candidates", []),
            max_candidates=self.options.max_candidates,
        )

    async def _validate_candidate_with_semaphore(
        self,
        candidate: SimilarIssueCandidate,
        semaphore: asyncio.Semaphore,
    ) -> SimilarIssueFinding:
        async with semaphore:
            return await self._validate_candidate(candidate)

    async def _validate_candidate(
        self,
        candidate: SimilarIssueCandidate,
    ) -> SimilarIssueFinding:
        schema_text = json.dumps(
            SIMILAR_ISSUE_VALIDATION_SCHEMA,
            ensure_ascii=False,
            indent=2,
        )
        prompt = self._build_validation_prompt(
            candidate,
            schema_text,
        )
        result = await run_opencode_task(
            task_name=f"similar issue validation {candidate.code_location}",
            task_type="variant_hunt",
            prompt=prompt,
            required_capability=self.options.required_capability,
            output_schema=SIMILAR_ISSUE_VALIDATION_SCHEMA,
            session_id=None,
            config_path=self.options.config_path,
            output=self.options.output,
            cancel_event=self.options.cancel_event,
        )
        if getattr(result, "status", "") != "success":
            raise RuntimeError(
                f"candidate validation ended with status {getattr(result, 'status', '')!r}"
            )
        structured = getattr(result, "structured", None)
        if not isinstance(structured, dict):
            raise TypeError("candidate validation did not return a JSON object")
        return _normalize_finding(structured, fallback_candidate=candidate)

    def _build_candidate_prompt(
        self,
        schema_text: str,
    ) -> str:
        candidate_limit = (
            f"- 最多输出 {self.options.max_candidates} 个候选位置。\n"
            if self.options.max_candidates is not None
            else ""
        )
        return f"""\
你是网络安全代码审计候选发现 agent。

任务目标：
根据下面给出的历史漏洞描述、漏洞根因和漏洞代码，在目标范围内全面排查，找出可能出现同类问题的代码位置，输出候选列表供下一步逐项并行审计。

候选发现要求：
- 这一步只负责发现候选代码位置，不负责确认候选是否真实存在漏洞。
- 不要对候选进行完整数据流分析、可利用性分析或漏洞定性。
- 只要代码位置在输入来源、危险操作、缺失的安全控制、数据处理方式或业务场景中的任一方面与历史问题存在相似性，就应加入候选。
- 无法确认输入是否可控、调用路径是否可达或校验是否有效时，不要因此排除候选。
- 以召回率为优先，允许误报；不要只输出最有把握的少量位置，也不要在发现几个候选后提前停止。
- 必须检索整个目标范围。同一个代码位置只输出一次；没有候选时输出空列表。
- 每个候选对象只能包含 `code_location` 一个字段，不要输出原因、代码片段、置信度、漏洞结论或修复建议。
- `code_location` 必须来自当前代码仓库中的真实代码，使用相对文件路径。
- `code_location` 支持三种行号形式：单行 `path/to/file.py:42`、连续范围 `path/to/file.py:42-57`、多个行号或范围 `path/to/file.py:42,48-53,61`。
- 多个行号或范围必须属于同一个文件；涉及不同文件时分别输出候选。
- 行号应指向最能代表候选问题的关键代码，可以覆盖相互关联的多行，不要使用 import 行或无关代码行。
{candidate_limit}- 最终回复必须只包含一个严格符合 JSON Schema 的 JSON 对象，不要输出 Markdown 或解释文字。

历史漏洞描述：
{self.known_issue["description"]}

历史漏洞根因：
{self.known_issue["root_cause"]}

历史漏洞代码：
```text
{self.known_issue["original_code"]}
```

目标范围：
{self.options.search_scope}

JSON Schema:
{schema_text}
"""

    def _build_validation_prompt(
        self,
        candidate: SimilarIssueCandidate,
        schema_text: str,
    ) -> str:
        candidate_json = json.dumps(
            candidate.to_dict(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        return f"""\
你是网络安全代码审计 agent。你正在执行相似问题排查的单个候选审计步骤。

任务目标：
1. 根据候选代码位置读取并审计当前仓库中的实际代码。
2. 结合历史漏洞描述、漏洞根因和漏洞代码，确认候选是否存在同构或高度相似的安全问题。
3. 只输出这个候选的审计结论，不要扩展审计其它候选。

审计要求：
- 必须检查候选代码及理解问题所需的上下文，包括相关调用者、被调用者、安全校验和配置。
- 必须对比历史漏洞与候选的攻击者可控输入、数据传递、缺失或无效的安全控制、危险操作、触发路径和业务语义。
- 只有候选问题的根因和利用条件与历史漏洞同构或高度相似时，`similar_issue_exists` 才能为 true。
- `severity` 在没有相似问题时必须为 "none"。
- `code_location` 必须保留输入候选位置；如发现更准确的关联行，可在相同文件内调整行号、范围或多个行号。
- `evidence` 必须引用当前仓库中的具体文件、行号、函数、代码行为和数据流，不能只写主观判断。
- 最终回复必须只包含一个严格符合 JSON Schema 的 JSON 对象，不要输出 Markdown 或解释文字。

历史漏洞描述：
{self.known_issue["description"]}

历史漏洞根因：
{self.known_issue["root_cause"]}

历史漏洞代码：
```text
{self.known_issue["original_code"]}
```

目标范围：
{self.options.search_scope}

候选位置：
{candidate_json}

JSON Schema:
{schema_text}
"""

    def _validate_options(self) -> None:
        if not self.known_issue_text.strip():
            raise ValueError("known_issue must not be empty")
        if not str(self.options.search_scope or "").strip():
            raise ValueError("search_scope must not be empty")
        if (
            self.options.max_candidates is not None
            and self.options.max_candidates < 1
        ):
            raise ValueError("max_candidates must be >= 1 or None")
        if self.options.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if self.options.required_capability not in {"low", "high"}:
            raise ValueError("required_capability must be 'low' or 'high'")


async def find_similar_issue(
    known_issue: str | dict[str, Any] | FindSimilarIssueOptions,
    **overrides: Any,
) -> FindSimilarIssueResult:
    """Find and validate issues similar to a known issue."""
    if isinstance(known_issue, FindSimilarIssueOptions):
        if overrides:
            values = {**known_issue.__dict__, **overrides}
            options = FindSimilarIssueOptions(**values)
        else:
            options = known_issue
    else:
        options = FindSimilarIssueOptions(known_issue=known_issue, **overrides)
    return await FindSimilarIssueRunner(options).run()


async def run_similar_issues_audit(
    issue_description: str,
    issue_root_analysis: str,
    issue_code: str,
    code_path: str | os.PathLike[str],
) -> list[dict[str, Any]]:
    """Audit one code path and return confirmed issues similar to a known issue."""
    description = _require_interface_text(
        "issue_description",
        issue_description,
    )
    root_analysis = _require_interface_text(
        "issue_root_analysis",
        issue_root_analysis,
    )
    original_code = _require_interface_text("issue_code", issue_code)
    audit_path = _require_interface_text("code_path", code_path)

    result = await find_similar_issue(
        {
            "description": description,
            "root_cause": root_analysis,
            "original_code": original_code,
        },
        search_scope=(
            "仅审计当前 Task Agent 项目范围内的以下代码路径，"
            f"不要检索或审计该路径之外的代码：{audit_path}"
        ),
    )
    return [
        finding.to_dict()
        for finding in result.findings
        if finding.similar_issue_exists
    ]


def _normalize_candidates(
    value: Any,
    *,
    max_candidates: int | None,
) -> list[SimilarIssueCandidate]:
    if not isinstance(value, list):
        return []

    candidates: list[SimilarIssueCandidate] = []
    seen_locations: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        code_location = _normalize_code_location(item.get("code_location"))
        if not code_location or code_location in seen_locations:
            continue
        seen_locations.add(code_location)
        candidates.append(SimilarIssueCandidate(code_location=code_location))
        if max_candidates is not None and len(candidates) >= max_candidates:
            break
    return candidates


def _normalize_finding(
    value: dict[str, Any],
    *,
    fallback_candidate: SimilarIssueCandidate,
) -> SimilarIssueFinding:
    exists = bool(value.get("similar_issue_exists"))
    severity = _clean_severity(value.get("severity"))
    if not exists:
        severity = "none"
    elif severity == "none":
        severity = "low"
    code_location = _normalize_code_location(value.get("code_location"))
    if (
        not code_location
        or _code_location_path(code_location)
        != _code_location_path(fallback_candidate.code_location)
    ):
        code_location = fallback_candidate.code_location
    return SimilarIssueFinding(
        code_location=code_location,
        similar_issue_exists=exists,
        severity=severity,
        title=_clean_text(value.get("title")),
        root_cause=_clean_text(value.get("root_cause")),
        evidence=_clean_text(value.get("evidence")),
        attack_path=_clean_text(value.get("attack_path")),
        similarity_analysis=_clean_text(value.get("similarity_analysis")),
        difference_analysis=_clean_text(value.get("difference_analysis")),
        recommendation=_clean_text(value.get("recommendation")),
        confidence=_clean_confidence(value.get("confidence")),
    )


def _normalize_known_issue(value: str | dict[str, Any]) -> dict[str, str]:
    if isinstance(value, str):
        description = value.strip()
        if not description:
            raise ValueError("known_issue must not be empty")
        return {
            "description": description,
            "root_cause": "(未单独提供，请结合漏洞描述理解)",
            "original_code": "(未单独提供)",
        }
    if not isinstance(value, dict):
        raise TypeError("known_issue must be a string or dict")

    description = _first_text(
        value,
        "description",
        "vulnerability_description",
        "issue_description",
    )
    root_cause = _first_text(value, "root_cause", "cause")
    original_code = _first_text(
        value,
        "original_code",
        "vulnerability_code",
        "code",
    )
    if not any((description, root_cause, original_code)):
        raise ValueError("known_issue must not be empty")
    return {
        "description": description or "(未单独提供)",
        "root_cause": root_cause or "(未单独提供)",
        "original_code": original_code or "(未单独提供)",
    }


def _format_known_issue(value: dict[str, str]) -> str:
    return "\n".join(
        (
            f"漏洞描述：{value['description']}",
            f"漏洞根因：{value['root_cause']}",
            f"漏洞代码：{value['original_code']}",
        )
    )


def _first_text(value: dict[str, Any], *keys: str) -> str:
    for key in keys:
        text = _clean_text(value.get(key))
        if text:
            return text
    return ""


def _require_interface_text(name: str, value: Any) -> str:
    text = _clean_text(value)
    if not text:
        raise ValueError(f"{name} must not be empty")
    return text


_LINE_SEGMENT_RE = re.compile(
    r"^(?P<start>[1-9]\d*)(?:\s*-\s*(?P<end>[1-9]\d*))?$"
)


def _normalize_code_location(value: Any) -> str:
    text = _clean_text(value)
    file_path, separator, line_spec = text.rpartition(":")
    file_path = file_path.strip()
    line_spec = line_spec.strip()
    if not separator or not file_path or not line_spec:
        return ""

    normalized_segments: list[str] = []
    seen_segments: set[str] = set()
    for raw_segment in line_spec.split(","):
        match = _LINE_SEGMENT_RE.fullmatch(raw_segment.strip())
        if match is None:
            return ""
        start = int(match.group("start"))
        end_text = match.group("end")
        if end_text is None:
            segment = str(start)
        else:
            end = int(end_text)
            if end < start:
                return ""
            segment = f"{start}-{end}"
        if segment not in seen_segments:
            normalized_segments.append(segment)
            seen_segments.add(segment)
    if not normalized_segments:
        return ""
    return f"{file_path}:{','.join(normalized_segments)}"


def _code_location_path(value: str) -> str:
    return value.rpartition(":")[0]


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _clean_confidence(value: Any) -> CandidateConfidence:
    confidence = _clean_text(value).lower()
    if confidence in {"high", "medium", "low"}:
        return confidence  # type: ignore[return-value]
    return "low"


def _clean_severity(value: Any) -> FindingSeverity:
    severity = _clean_text(value).lower()
    if severity in {"critical", "high", "medium", "low", "none"}:
        return severity  # type: ignore[return-value]
    return "none"
