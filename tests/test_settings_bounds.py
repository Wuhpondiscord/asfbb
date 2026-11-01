import asyncio
from unittest.mock import patch
import pytest
from pydantic import ValidationError
from app import main, pipeline

@pytest.mark.parametrize("depth", [1,2,3,4,5])
def test_depth_supported(depth):
    assert main.PipelineOptions(katana_depth=depth).katana_depth == depth

@pytest.mark.parametrize("depth", [0,6,-1])
def test_depth_rejected(depth):
    with pytest.raises(ValidationError):
        main.PipelineOptions(katana_depth=depth)

@pytest.mark.parametrize("name,value", [
    ("endpoint_limit",101),("httpx_limit",11),
    ("zap_endpoint_limit",11),("request_budget",101)])
def test_option_bounds(name,value):
    with pytest.raises(ValidationError):
        main.PipelineOptions(**{name:value})

def test_katana_depth_reaches_binary():
    async def fake(args,timeout):
        assert args[args.index("-d")+1]=="5"
        return [],"completed"
    with patch.object(pipeline,"execute",fake):
        result=asyncio.run(pipeline.katana("https://example.org","example.org","Test",5))
    assert result["status"]=="completed"

def test_serialization_roundtrip():
    opts=main.PipelineOptions(katana_depth=5,endpoint_limit=100,httpx_limit=10)
    assert main.PipelineOptions(**opts.model_dump())==opts

def test_logging_event_shape():
    main.scan_events.clear()
    main.log_event({"owner":"test","id":"job1","target":"https://example.org"},"stage_finished",
                   module="katana",elapsed_ms=100,status="completed")
    assert main.scan_events[-1]["elapsed_ms"]==100
