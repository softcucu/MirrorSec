from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from main import _print_opencode_session_lifecycle


class SessionLoggingTests(unittest.TestCase):
    def test_prints_only_requested_session_lifecycle_events(self) -> None:
        lines = [
            "[git_history][pending][task] QUEUED task=task-1",
            "[git_history][ses_new][session] START mode=created directory=/repo",
            "[git_history][ses_new][session] CREATED",
            "[git_history][ses_new][tool] CALL name=read path=/repo/a.py",
            "[git_history][ses_new][session] STATUS status=busy",
            "[git_history][ses_new][session] STOP status=success retained=true",
            "[git_history][ses_new][session] COMPLETED",
            "[variant_hunt][ses_bad][session] STOP status=failure retained=true error=boom",
            "[variant_hunt][ses_bad][session] FAILED status=failure",
            (
                "[variant_hunt][ses_bad][session] RETRY 1/2 "
                "reason=boom next_session=new"
            ),
            (
                "[variant_hunt][ses_json][session] RETRYING "
                "attempt=2/3 next_session=same"
            ),
            (
                "[variant_hunt][ses_provider][session] RETRY "
                "attempt=3 message=rate-limited"
            ),
            "[variant_hunt][ses_old][session] START mode=continued directory=/repo",
        ]

        output = io.StringIO()
        with redirect_stdout(output):
            for line in lines:
                _print_opencode_session_lifecycle(line)

        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "[opencode] SESSION_CREATED session_id=ses_new",
                "[opencode] SESSION_COMPLETED session_id=ses_new",
                "[opencode] SESSION_FAILED session_id=ses_bad status=failure",
                (
                    "[opencode] SESSION_RETRYING session_id=ses_bad "
                    "attempt=1/2 next_session=new"
                ),
                (
                    "[opencode] SESSION_RETRYING session_id=ses_json "
                    "attempt=2/3 next_session=same"
                ),
                (
                    "[opencode] SESSION_RETRYING session_id=ses_provider "
                    "attempt=3"
                ),
            ],
        )


if __name__ == "__main__":
    unittest.main()
