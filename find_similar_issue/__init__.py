"""Find issues similar to a known issue through the Task Agent interface."""

from .analyzer import (
    SIMILAR_ISSUE_FINDING_SCHEMA,
    SIMILAR_ISSUE_METHOD_SCHEMA,
    SIMILAR_ISSUES_AUDIT_SCHEMA,
    FindSimilarIssueOptions,
    FindSimilarIssueResult,
    FindSimilarIssueRunner,
    SimilarIssueFinding,
    find_similar_issue,
    run_similar_issues_audit,
)

__all__ = [
    "SIMILAR_ISSUE_FINDING_SCHEMA",
    "SIMILAR_ISSUE_METHOD_SCHEMA",
    "SIMILAR_ISSUES_AUDIT_SCHEMA",
    "FindSimilarIssueOptions",
    "FindSimilarIssueResult",
    "FindSimilarIssueRunner",
    "SimilarIssueFinding",
    "find_similar_issue",
    "run_similar_issues_audit",
]
