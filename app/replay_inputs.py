"""Validated one-asset replay inputs; raw requests are never public options."""
import json
import math
import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def relative_path(value):
    p = urlsplit(value)
    if (not value.startswith("/") or value.startswith("//") or p.scheme or p.netloc
            or p.query or p.fragment or ".." in value or any(c in value for c in "\r\n\x00\\")):
        raise ValueError("Use a same-origin path without query or fragment")
    return value


def json_pointer(value):
    if value and not value.startswith("/") or re.search(r"~(?![01])", value):
        raise ValueError("Use an RFC 6901 JSON pointer")
    return value


def key(value):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,49}", value) or value in ("__proto__", "constructor", "prototype"):
        raise ValueError("Use a simple property name")
    return value


def scalar(value):
    if type(value) not in (str, int, float, bool, type(None)):
        raise ValueError("Expected a JSON scalar")
    if isinstance(value, str) and len(value) > 256 or isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Expected a bounded finite JSON scalar")
    return value


class PrivateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    @model_validator(mode="after")
    def bounded_document(self):
        if len(json.dumps(self.model_dump(), allow_nan=False).encode("utf-8")) > 24000:
            raise ValueError("Replay profile exceeds 24,000 bytes")
        return self


class JsonMatch(PrivateModel):
    pointer: str = Field(default="", max_length=200)
    equals: Any
    _pointer = field_validator("pointer")(json_pointer)
    _equals = field_validator("equals")(scalar)


class ReplayRequest(PrivateModel):
    path: str = Field(min_length=1, max_length=250)
    method: Literal["GET", "POST"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict, max_length=16)
    query: dict[str, str] = Field(default_factory=dict, max_length=16)
    json_body: dict[str, Any] | None = None
    _path = field_validator("path")(relative_path)

    @field_validator("headers")
    @classmethod
    def valid_headers(cls, values):
        protected = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "expect",
                     "accept-encoding", "content-type", "user-agent", "te", "trailer"}
        seen = set()
        for name, value in values.items():
            lowered = name.lower()
            if (not re.fullmatch(r"[A-Za-z0-9-]{1,60}", name) or lowered in seen
                    or lowered in protected or lowered.startswith("proxy-") or len(value) > 2000
                    or any(ord(c) < 32 or ord(c) > 126 for c in value)):
                raise ValueError("Invalid, duplicate or protected request header")
            seen.add(lowered)
        if sum(len(k) + len(v) for k, v in values.items()) > 6000:
            raise ValueError("Request headers exceed the profile limit")
        return values

    @field_validator("query")
    @classmethod
    def valid_query(cls, values):
        for name, value in values.items():
            key(name)
            if len(value) > 1000 or any(c in value for c in "\r\n\x00"):
                raise ValueError("Invalid query value")
        return values

    @field_validator("json_body")
    @classmethod
    def valid_body(cls, value):
        if value is None:
            return value
        nodes = [0]
        def walk(item, depth=0):
            nodes[0] += 1
            if depth > 6 or nodes[0] > 256:
                raise ValueError("JSON body is too complex")
            if isinstance(item, dict):
                for name, child in item.items():
                    key(name)
                    walk(child, depth + 1)
            elif isinstance(item, list):
                for child in item:
                    walk(child, depth + 1)
            elif type(item) not in (str, int, float, bool, type(None)):
                raise ValueError("Invalid JSON body value")
        walk(value)
        try:
            if len(json.dumps(value, allow_nan=False).encode("utf-8")) > 8192:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("JSON body exceeds the bounded JSON profile") from None
        return value

    @model_validator(mode="after")
    def method_body(self):
        if self.method == "GET" and self.json_body is not None:
            raise ValueError("GET uses query fields; JSON bodies require POST")
        if self.method == "POST" and self.json_body is None:
            raise ValueError("POST requires a JSON object body")
        return self


def existing_field(request, name):
    values = request.query if request.method == "GET" else request.json_body
    if not values or name not in values or not isinstance(values[name], str):
        raise ValueError("Selected field must exist as a top-level string in query or JSON body")
    return values[name]


class StateCounter(PrivateModel):
    request: ReplayRequest
    field: str = Field(min_length=1, max_length=50)
    pointer: str = Field(min_length=1, max_length=200)
    _field = field_validator("field")(key)
    _pointer = field_validator("pointer")(pointer)

    @model_validator(mode="after")
    def read_only(self):
        if self.request.method != "GET":
            raise ValueError("State verification must be GET")
        existing_field(self.request, self.field)
        return self


class RaceReplay(PrivateModel):
    request: ReplayRequest
    field: str = Field(min_length=1, max_length=50)
    control_value: str = Field(min_length=1, max_length=128)
    parallel_value: str = Field(min_length=1, max_length=128)
    success: JsonMatch
    verification: StateCounter | None = None
    _field = field_validator("field")(key)

    @model_validator(mode="after")
    def fixtures(self):
        existing_field(self.request, self.field)
        if self.control_value == self.parallel_value or any(c in self.control_value + self.parallel_value for c in "\r\n\x00"):
            raise ValueError("Supply distinct fresh control and parallel fixture values")
        return self


class NoSQLReplay(PrivateModel):
    request: ReplayRequest
    field: str = Field(min_length=1, max_length=50)
    success: JsonMatch
    _field = field_validator("field")(key)

    @model_validator(mode="after")
    def baseline(self):
        if len(existing_field(self.request, self.field)) > 128:
            raise ValueError("Baseline field exceeds 128 characters")
        return self
