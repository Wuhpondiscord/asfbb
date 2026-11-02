import asyncio
from unittest.mock import AsyncMock, patch

from app.zap_control import wait_for_passive_queue


def test_zap_stalled_global_record_reports_partial_without_waiting_full_window():
    calls = []
    async def fake(client, component, action, params):
        calls.append(action)
        if action=="view/recordsToScan":
            return {"recordsToScan": 1}
        return {"currentTasks": [{"name":"slow rule","url":"https://other.example/"}]}
    with patch("app.zap_control.asyncio.sleep",new_callable=AsyncMock):
        outcome=asyncio.run(wait_for_passive_queue(
            object(),fake,"example.org",limit=30,interval=0.75,stall_checks=6))
    assert outcome["remaining"]==1
    assert outcome["stalled"] is True
    assert outcome["checks"]<30
    assert outcome["host_tasks_running"]==0
    assert outcome["global_tasks_running"]==1
    assert "passive coverage is incomplete" in outcome["reason"]


def test_zap_current_host_still_scanning_waits_for_queue_to_drain():
    counts=[1]*9+[0]
    async def fake(client, component, action, params):
        if action=="view/recordsToScan":
            return {"recordsToScan":counts.pop(0)}
        return {"currentTasks":[{"url":"https://example.org/doc"}]}
    with patch("app.zap_control.asyncio.sleep",new_callable=AsyncMock):
        outcome=asyncio.run(wait_for_passive_queue(
            object(),fake,"example.org",limit=30,interval=0.75,stall_checks=4))
    assert outcome["remaining"]==0
    assert outcome["checks"]==10
    assert outcome["stalled"] is False


def test_zap_does_not_falsely_claim_completion_if_queue_is_still_pending():
    async def fake(client, component, action, params):
        if action=="view/recordsToScan":
            return {"recordsToScan":1}
        return {}
    with patch("app.zap_control.asyncio.sleep",new_callable=AsyncMock):
        outcome=asyncio.run(wait_for_passive_queue(
            object(),fake,"example.org",limit=5,interval=0,stall_checks=2))
    assert outcome["remaining"]==1
    assert outcome["stalled"] is False


def test_nested_zap_current_tasks_api_keeps_waiting_for_own_host():
    counts=[1]*8+[0]
    async def fake(client,component,action,params):
        if action=="view/recordsToScan":
            return {"recordsToScan": counts.pop(0)}
        return {"currentTasks":[{"currentTasks":{"name":"pscan rule",
                                                 "url":"https://example.org/",
                                                 "time":"4200"}}]}
    with patch("app.zap_control.asyncio.sleep",new_callable=AsyncMock):
        out=asyncio.run(wait_for_passive_queue(object(),fake,"example.org",
              limit=20,interval=0,stall_checks=3))
    assert out["remaining"]==0
    assert out["checks"]==9


def test_unknown_zap_task_shape_keeps_queue_result_partial():
    async def fake(client,component,action,params):
        return {"recordsToScan":1} if action=="view/recordsToScan" else {
          "currentTasks":[{"currentTasks":{"name":"missing-url"}}]}
    with patch("app.zap_control.asyncio.sleep",new_callable=AsyncMock):
        result=asyncio.run(wait_for_passive_queue(object(),fake,"example.org",
              limit=7,interval=0,stall_checks=2))
    assert result["stalled"] is False
    assert result["checks"]==7


def test_large_response_active_task_can_finish_after_the_previous_30_check_cutoff():
    counts = [1] * 65 + [0]
    progress = []
    async def fake(client, component, action, params):
        if action == "view/recordsToScan":
            return {"recordsToScan": counts.pop(0)}
        return {"currentTasks": [{"currentTasks": {"name": "large response rule",
                                                  "url": "https://example.org/large"}}]}
    with patch("app.zap_control.asyncio.sleep", new_callable=AsyncMock):
        result = asyncio.run(wait_for_passive_queue(object(), fake, "example.org",
                            limit=400, interval=0.75, stall_checks=6,
                            timeout_seconds=120, on_progress=progress.append))
    assert result["remaining"] == 0 and result["checks"] == 66
    assert result["stalled"] is False and result["reason"] == ""
    assert any(row["host_tasks_running"] == 1 for row in progress)
    assert all("url" not in row and "large response rule" not in str(row) for row in progress)


def test_active_task_does_not_bypass_hard_passive_deadline():
    from types import SimpleNamespace
    clock = [0.0]
    async def sleep(seconds):
        clock[0] += seconds
    async def fake(client, component, action, params):
        return ({"recordsToScan": 1} if action == "view/recordsToScan" else
                {"currentTasks": [{"url": "https://example.org/large"}]})
    with patch("app.zap_control.time", SimpleNamespace(monotonic=lambda: clock[0])), \
         patch("app.zap_control.asyncio.sleep", sleep):
        result = asyncio.run(wait_for_passive_queue(object(), fake, "example.org",
                            limit=400, interval=0.75, stall_checks=2, timeout_seconds=15))
    assert result["remaining"] == 1 and result["deadline_reached"] is True
    assert result["host_tasks_running"] == 1 and result["elapsed_seconds"] == 15
    assert result["checks"] < 30 and "coverage is incomplete" in result["reason"]


def test_queue_api_call_itself_cannot_hold_the_shared_zap_slot_past_deadline():
    async def fake(*args):
        await asyncio.Event().wait()
    result = asyncio.run(wait_for_passive_queue(object(), fake, "example.org",
                        limit=400, interval=0.75, stall_checks=2, timeout_seconds=0.01))
    assert result["remaining"] == -1 and result["deadline_reached"]
    assert "unknown number" in result["reason"]
