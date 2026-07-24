"""Find issues similar to a known issue through the Task Agent interface."""

from .analyzer import (
    CANDIDATE_DISCOVERY_SCHEMA,
    SIMILAR_ISSUE_VALIDATION_SCHEMA,
    FindSimilarIssueOptions,
    FindSimilarIssueResult,
    FindSimilarIssueRunner,
    SimilarIssueCandidate,
    SimilarIssueFinding,
    find_similar_issue,
    run_similar_issues_audit,
)

__all__ = [
    "CANDIDATE_DISCOVERY_SCHEMA",
    "SIMILAR_ISSUE_VALIDATION_SCHEMA",
    "FindSimilarIssueOptions",
    "FindSimilarIssueResult",
    "FindSimilarIssueRunner",
    "SimilarIssueCandidate",
    "SimilarIssueFinding",
    "find_similar_issue",
    "run_similar_issues_audit",
]
