"""Command line entry point for git history analysis."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .analyzer import GitHistoryAnalysisOptions, analyze_git_history


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m git_history_analysis",
        description="并发分析 git commit，识别网络安全漏洞修复并保存到 SQLite。",
    )
    parser.add_argument("--repo", default=".", help="待分析的 git 仓库路径。")
    parser.add_argument(
        "--db",
        default="git_history_analysis.sqlite3",
        help="SQLite 结果数据库路径。",
    )
    parser.add_argument(
        "--revision-range",
        default="HEAD",
        help="传给 git rev-list 的 revision range，默认 HEAD。",
    )
    parser.add_argument("--since", default=None, help="只分析此时间之后的 commit。")
    parser.add_argument("--until", default=None, help="只分析此时间之前的 commit。")
    parser.add_argument(
        "--max-commits",
        type=int,
        default=None,
        help="最多分析最近 N 个 commit。",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="并发提交给 LLM agent 的 commit 数。",
    )
    parser.add_argument(
        "--include-merges",
        action="store_true",
        help="包含 merge commit；默认跳过 merge commit。",
    )
    parser.add_argument(
        "--reanalyze",
        action="store_true",
        help="重新分析已经有完成记录的 commit。",
    )
    parser.add_argument(
        "--config-path",
        default=None,
        help="Task Agent 独立运行配置 YAML 路径。",
    )
    parser.add_argument(
        "--max-patch-chars",
        type=int,
        default=120_000,
        help="单个 commit diff 传给模型的最大字符数。",
    )
    parser.add_argument(
        "--max-original-code-chars",
        type=int,
        default=60_000,
        help="父版本原始代码片段传给模型的最大字符数。",
    )
    return parser


async def _amain() -> None:
    args = _build_parser().parse_args()
    summary = await analyze_git_history(
        GitHistoryAnalysisOptions(
            repo_path=Path(args.repo),
            db_path=Path(args.db),
            revision_range=args.revision_range,
            since=args.since,
            until=args.until,
            max_commits=args.max_commits,
            concurrency=args.concurrency,
            include_merges=args.include_merges,
            skip_analyzed=not args.reanalyze,
            config_path=args.config_path,
            max_patch_chars=args.max_patch_chars,
            max_original_code_chars=args.max_original_code_chars,
        )
    )
    print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2), flush=True)


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
