import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app import client_modules, final_modules


async def no_sleep(*args): pass


async def clean_retire_report(args, timeout):
    Path(args[args.index("--outputpath") + 1]).write_text(json.dumps({"data": [], "errors": []}))
    return [], "completed"


def test_balanced_profile_finishes_all_five_inline_samples_instead_of_truncating_at_four():
    html = ("<html>" + "".join("<script>const sample" + str(i) + "=1;</script>" for i in range(5)) + "</html>").encode()
    async def fetch(url, agent, cap): return html, "text/html", url
    with patch.object(client_modules, "fetch_sample", fetch), \
         patch.object(client_modules, "execute", clean_retire_report):
        result = asyncio.run(client_modules.retirejs(
            "https://example.org/", "example.org", "Test", 1.5, [], profile="balanced"))
    assert result["status"] == "completed"
    assert result["sampled_files"] == 5
    assert result["coverage"]["eligible_files"] == 5
    assert result["coverage"]["engine_status"] == "completed"
    assert not result["coverage"]["coverage_limited"]


def test_oversized_bundles_do_not_use_up_all_slots_before_later_small_scripts():
    seen = []
    async def fetch(url, agent, cap):
        if url == "https://example.org/":
            html = "<html>" + "".join('<script src="/s' + str(i) + '.js"></script>' for i in range(7)) + "</html>"
            return html.encode(), "text/html", url
        seen.append(url)
        if len(seen) <= 3:
            raise client_modules.FetchProblem("response exceeds sample byte limit")
        return b"/* fixture */", "text/javascript", url
    with patch.object(client_modules, "fetch_sample", fetch), \
         patch.object(client_modules, "execute", clean_retire_report), \
         patch.object(client_modules.asyncio, "sleep", no_sleep):
        result = asyncio.run(client_modules.retirejs(
            "https://example.org/", "example.org", "Test", 1.5, [], profile="quick"))
    assert len(seen) == 7 and result["sampled_files"] == 4
    assert result["coverage"]["oversized"] == 3
    assert result["coverage"]["engine_status"] == "completed"
    assert result["status"] == "partial"  # Omitted bundles remain explicit coverage gaps.


@pytest.mark.parametrize("name,minutes,deadline", [("current", "1", 180), ("quick", "1", 180), ("balanced", "2", 300), ("thorough", "5", 600)])
def test_amass_profile_leaves_time_for_internal_deadline_and_output_flush(name, minutes, deadline):
    async def execute(args, timeout):
        assert args[args.index("-timeout") + 1] == minutes
        assert timeout == deadline
        Path(args[args.index("-o") + 1]).write_text("a.example.org\n")
        return [], "completed"
    with patch.object(final_modules, "execute", execute):
        result = asyncio.run(final_modules.run("amass", "https://example.org/", "example.org", "Test", 1.5, profile=name))
    assert result["hosts"] == ["a.example.org"] and result["deadline_seconds"] == deadline
    assert result["endpoints"] == []
