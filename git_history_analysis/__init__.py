"""Analyze git history with the Task Agent git_history interface."""

from .analyzer import (
    GitHistoryAnalysisOptions,
    GitHistoryAnalysisSummary,
    GitHistoryAnalyzer,
    analyze_git_history,
)

__all__ = [
    "GitHistoryAnalysisOptions",
    "GitHistoryAnalysisSummary",
    "GitHistoryAnalyzer",
    "analyze_git_history",
]
