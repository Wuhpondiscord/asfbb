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
    assert "Some alerts may arrive later" in outcome["reason"]


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
