from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .summarize_reports import LocalLlamaClient


PROMPT_VERSION = "lazarus-event-enrichment-v1"
MODEL_NAME = "Qwen3-4B-Q4_K_M"
THREAT_TYPES = (
    "钓鱼攻击",
    "C2通信",
    "漏洞利用",
    "恶意软件",
    "凭证窃取",
    "供应链攻击",
    "勒索软件",
    "APT攻击",
    "其他",
)
FORBIDDEN_DISPLAY_PHRASES = (
    "需要人工复核",
    "需人工审核",
    "待审核",
    "待确认",
    "置信度不足",
    "低于阈值",
    "当前采集器",
    "未调用外部",
    "具体技术细节应由人工",
)


class ModelUnavailableError(RuntimeError):
    """The shared local model cannot safely serve a request."""


class ModelOutputError(RuntimeError):
    """The model output failed deterministic evidence validation."""


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().casefold() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SharedModelConfig:
    project_root: Path
    enabled: bool = True
    base_url: str = "http://127.0.0.1:8091"
    context_size: int = 16384
    threads: int = 6
    request_timeout: int = 900
    startup_timeout: int = 180
    max_source_chars: int = 50000

    @classmethod
    def from_project_root(cls, project_root: Path) -> "SharedModelConfig":
        return cls(
            project_root=project_root.resolve(),
            enabled=_env_bool("QIANXIN_SHARED_MODEL_ENABLED", True),
            base_url=os.environ.get(
                "QIANXIN_SHARED_MODEL_BASE_URL", "http://127.0.0.1:8091"
            ).rstrip("/"),
            context_size=int(
                os.environ.get("QIANXIN_SHARED_MODEL_CONTEXT_SIZE", "16384")
            ),
            threads=int(os.environ.get("QIANXIN_SHARED_MODEL_THREADS", "6")),
            request_timeout=int(
                os.environ.get("QIANXIN_SHARED_MODEL_REQUEST_TIMEOUT", "900")
            ),
            startup_timeout=int(
                os.environ.get("QIANXIN_SHARED_MODEL_STARTUP_TIMEOUT", "180")
            ),
            max_source_chars=int(
                os.environ.get("QIANXIN_SHARED_MODEL_MAX_SOURCE_CHARS", "50000")
            ),
        )

    @property
    def server_exe(self) -> Path:
        return (
            self.project_root
            / "tools"
            / "llama.cpp"
            / "b10278"
            / "llama-server.exe"
        )

    @property
    def model_path(self) -> Path:
        return (
            self.project_root
            / "data"
            / "models"
            / "llm"
            / "Qwen3-4B-Q4_K_M.gguf"
        )


class SharedModelRuntime:
    """Own one loopback llama-server process for every local collection task."""

    def __init__(self, config: SharedModelConfig) -> None:
        parsed = urlparse(config.base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.port is None
        ):
            raise ValueError("The shared llama endpoint must be loopback HTTP with a port")
        self.config = config
        self.client = LocalLlamaClient(
            config.base_url, timeout=config.request_timeout
        )
        self._start_lock = threading.Lock()
        self._inference_lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._handles: tuple[Any, Any] | None = None
        self._adopted = False

    def _health(self, timeout: float = 2.0) -> bool:
        request = urllib.request.Request(self.config.base_url + "/health")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                value = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError, urllib.error.URLError):
            return False
        return value.get("status") == "ok"

    def status(self) -> dict[str, Any]:
        owned = self._process is not None and self._process.poll() is None
        return {
            "enabled": self.config.enabled,
            "configured": self.config.server_exe.is_file()
            and self.config.model_path.is_file(),
            "running": self._health(),
            "owned_by_api": owned or self._adopted,
            "model": MODEL_NAME,
            "runtime": "llama.cpp",
            "context_size": self.config.context_size,
        }

    def ensure_ready(self) -> dict[str, Any]:
        if not self.config.enabled:
            raise ModelUnavailableError("Shared model service is disabled")
        if not self.config.server_exe.is_file():
            raise ModelUnavailableError("llama-server executable is unavailable")
        if not self.config.model_path.is_file():
            raise ModelUnavailableError("Qwen model file is unavailable")
        with self._start_lock:
            if self._process is not None and self._process.poll() is None:
                if self._health():
                    return self.status()
                self.close()
            elif self._process is not None:
                self.close()
            if self._health():
                if self._server_matches_config():
                    self._adopted = True
                    return self.status()
                raise ModelUnavailableError(
                    "The configured model port is occupied by a different process"
                )
            self._start()
            try:
                self.client.wait_until_ready(self.config.startup_timeout)
            except Exception as exc:
                self.close()
                raise ModelUnavailableError(
                    f"Shared model failed to become ready: {type(exc).__name__}"
                ) from exc
            return self.status()

    def _server_matches_config(self) -> bool:
        try:
            props = self.client._request("GET", "/props")
            actual_model = os.path.normcase(
                os.path.abspath(str(props.get("model_path") or ""))
            )
            expected_model = os.path.normcase(
                os.path.abspath(str(self.config.model_path))
            )
            context = int(
                props["default_generation_settings"]["n_ctx"]
            )
            slots = int(props.get("total_slots", 0))
        except (KeyError, TypeError, ValueError, OSError, urllib.error.URLError):
            return False
        return (
            actual_model == expected_model
            and context == self.config.context_size
            and slots == 1
        )

    def _start(self) -> None:
        self._adopted = False
        parsed = urlparse(self.config.base_url)
        log_root = self.config.project_root / "logs" / "shared-model"
        log_root.mkdir(parents=True, exist_ok=True)
        stdout_handle = (log_root / "llama-server.stdout.log").open("ab")
        stderr_handle = (log_root / "llama-server.stderr.log").open("ab")
        command = [
            str(self.config.server_exe),
            "-m",
            str(self.config.model_path),
            "--host",
            "127.0.0.1",
            "--port",
            str(parsed.port),
            "-c",
            str(self.config.context_size),
            "-t",
            str(self.config.threads),
            "-tb",
            str(max(self.config.threads, 12)),
            "--parallel",
            "1",
            "--reasoning",
            "off",
            "--no-webui",
        ]
        try:
            self._process = subprocess.Popen(
                command,
                cwd=self.config.project_root,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                shell=False,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                ),
            )
        except Exception:
            stdout_handle.close()
            stderr_handle.close()
            raise
        self._handles = (stdout_handle, stderr_handle)

    def close(self) -> None:
        process, handles = self._process, self._handles
        self._process = None
        self._handles = None
        self._adopted = False
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        for handle in handles or ():
            handle.close()

    def enrich_lazarus(self, request: Mapping[str, Any]) -> dict[str, Any]:
        source_content = str(request.get("source_content") or "")
        source_sha256 = str(request.get("source_sha256") or "").casefold()
        actual_sha256 = hashlib.sha256(source_content.encode("utf-8")).hexdigest()
        if source_sha256 != actual_sha256:
            raise ModelOutputError("Source content hash does not match the request")
        if not source_content.strip():
            raise ModelOutputError("Source content is empty")
        if len(source_content) > self.config.max_source_chars:
            raise ModelOutputError("Source content exceeds the configured limit")

        self.ensure_ready()
        schema = _lazarus_schema()
        system = (
            "你是 APTHunter 的本地威胁情报结构化模块。只能根据用户提供的 SOURCE 文本输出"
            "中文事件文案和候选字段。不得补写 SOURCE 中没有的组织、国家、目标、恶意软件、"
            "日期、URL 或攻击结果。actor_mentions.name 必须逐字来自证据引文。每个判断都必须"
            "给出 SOURCE 中可定位的短引文；不确定时降低 confidence，不要猜测。只输出符合"
            "JSON Schema 的对象。factual_points 只保留 1 到 4 条关键事实，每段引文不超过"
            "200 字符，标题和描述避免重复。"
        )
        def build_user(source: str) -> str:
            return (
                f"报告标题：{request.get('report_title') or ''}\n"
                f"已知发布方：{request.get('publisher') or ''}\n"
                "以下边界内文本是唯一事实来源。\n"
                "<SOURCE>\n"
                f"{source}\n"
                "</SOURCE>\n"
                "生成一条可直接展示的一至两句中文客观描述。title_zh 应简洁包含来源明确支持的"
                "攻击者名称和主要活动；description_zh 不得包含采集、模型、审核或置信度等内部流程措辞。"
            )

        source_for_prompt = source_content
        context_size = self.client.context_size()
        prompt_budget = max(2048, context_size - 2200)
        user = build_user(source_for_prompt)
        prompt_tokens = self.client.token_count(system + "\n" + user)
        if prompt_tokens > prompt_budget:
            target_chars = max(
                2000,
                int(len(source_for_prompt) * prompt_budget / prompt_tokens * 0.92),
            )
            source_for_prompt = source_for_prompt[:target_chars]
            user = build_user(source_for_prompt + "\n[SOURCE TRUNCATED]")
            while (
                self.client.token_count(system + "\n" + user) > prompt_budget
                and len(source_for_prompt) > 2000
            ):
                source_for_prompt = source_for_prompt[: int(len(source_for_prompt) * 0.85)]
                user = build_user(source_for_prompt + "\n[SOURCE TRUNCATED]")
        with self._inference_lock:
            try:
                raw, timings = self.client.chat_json(
                    system, user, max_tokens=800, schema=schema
                )
            except Exception as exc:
                raise ModelOutputError(
                    f"Local model request failed: {type(exc).__name__}"
                ) from exc
        validated = validate_lazarus_output(raw, source_content)
        return {
            "schema_version": "1.0",
            "prompt_version": PROMPT_VERSION,
            "source_event_id": str(request.get("source_event_id") or ""),
            "source_sha256": actual_sha256,
            "model": MODEL_NAME,
            "runtime": "llama.cpp",
            **validated,
            "timings": {
                key: timings[key]
                for key in ("prompt_n", "predicted_n")
                if key in timings
            },
        }


def _bounded_string(max_length: int, min_length: int = 1) -> dict[str, Any]:
    # llama.cpp expands bounded strings inside repeated array items into a very
    # large grammar and rejects it before inference. Lengths remain enforced by
    # the deterministic validator after generation.
    del max_length, min_length
    return {"type": "string"}


def _lazarus_schema() -> dict[str, Any]:
    actor = {
        "type": "object",
        "additionalProperties": False,
        "required": ["name", "evidence_quote"],
        "properties": {
            "name": _bounded_string(160),
            "evidence_quote": _bounded_string(500),
        },
    }
    fact = {
        "type": "object",
        "additionalProperties": False,
        "required": ["text_zh", "evidence_quote"],
        "properties": {
            "text_zh": _bounded_string(500),
            "evidence_quote": _bounded_string(700),
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "title_zh",
            "description_zh",
            "threat_type",
            "threat_type_evidence_quote",
            "actor_mentions",
            "factual_points",
            "confidence",
        ],
        "properties": {
            "title_zh": _bounded_string(500),
            "description_zh": _bounded_string(2000, 10),
            "threat_type": {"type": "string", "enum": list(THREAT_TYPES)},
            "threat_type_evidence_quote": _bounded_string(700),
            "actor_mentions": {
                "type": "array",
                "maxItems": 5,
                "items": actor,
            },
            "factual_points": {
                "type": "array",
                "minItems": 1,
                "maxItems": 4,
                "items": fact,
            },
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        },
    }


def _normalize_evidence_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"\s+", " ", normalized).strip()


def _grounded(quote: str, source_content: str) -> bool:
    normalized_quote = _normalize_evidence_text(quote)
    if len(normalized_quote) < 4:
        return False
    return normalized_quote in _normalize_evidence_text(source_content)


def _display_text(value: Any, field: str, *, maximum: int) -> str:
    text = " ".join(str(value or "").split())
    if not text or len(text) > maximum:
        raise ModelOutputError(f"{field} is empty or too long")
    if not re.search(r"[\u4e00-\u9fff]", text):
        raise ModelOutputError(f"{field} is not Chinese display copy")
    if any(phrase in text for phrase in FORBIDDEN_DISPLAY_PHRASES):
        raise ModelOutputError(f"{field} contains an internal workflow phrase")
    return text


def validate_lazarus_output(
    raw: Mapping[str, Any], source_content: str
) -> dict[str, Any]:
    title = _display_text(raw.get("title_zh"), "title_zh", maximum=500)
    description = _display_text(
        raw.get("description_zh"), "description_zh", maximum=2000
    )
    if description[-1] not in "。！？.!?":
        description += "。"
    threat_type = str(raw.get("threat_type") or "")
    if threat_type not in THREAT_TYPES:
        raise ModelOutputError("threat_type is outside the controlled vocabulary")
    threat_quote = str(raw.get("threat_type_evidence_quote") or "").strip()
    if not _grounded(threat_quote, source_content):
        raise ModelOutputError("Threat type evidence is not grounded in SOURCE")

    actors: list[dict[str, str]] = []
    for item in raw.get("actor_mentions") or []:
        if not isinstance(item, Mapping):
            raise ModelOutputError("actor_mentions contains an invalid item")
        name = " ".join(str(item.get("name") or "").split())
        quote = str(item.get("evidence_quote") or "").strip()
        if not name or len(name) > 160 or not _grounded(quote, source_content):
            raise ModelOutputError("Actor evidence is invalid or ungrounded")
        if _normalize_evidence_text(name) not in _normalize_evidence_text(quote):
            raise ModelOutputError("Actor name is not present in its evidence quote")
        actors.append({"name": name, "evidence_quote": quote})

    facts: list[dict[str, str]] = []
    for item in raw.get("factual_points") or []:
        if not isinstance(item, Mapping):
            raise ModelOutputError("factual_points contains an invalid item")
        text_zh = _display_text(item.get("text_zh"), "factual_points", maximum=500)
        quote = str(item.get("evidence_quote") or "").strip()
        if not _grounded(quote, source_content):
            raise ModelOutputError("A factual point is not grounded in SOURCE")
        facts.append({"text_zh": text_zh, "evidence_quote": quote})
    if not facts:
        raise ModelOutputError("At least one grounded factual point is required")

    confidence = raw.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ModelOutputError("confidence must be between 0 and 1")
    return {
        "title_zh": title,
        "description_zh": description,
        "threat_type": threat_type,
        "threat_type_evidence_quote": threat_quote,
        "actor_mentions": actors,
        "factual_points": facts,
        "confidence": round(float(confidence), 3),
    }
