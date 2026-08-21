"""
Backends de LLM intercambiables: mock, ollama, openai.

# La gracia: el agente (agent.py) no sabe qué LLM usa. Le pide .chat() y listo.
# Cambiar de backend es cambiar una variable de entorno (SOC_LLM_BACKEND).
#
# - mock   : determinístico, no descarga nada. La demo SIEMPRE funciona.
# - ollama : modelo local (privacidad total, no manda logs a la nube).
# - openai : API compatible OpenAI (rápido y consistente).
"""
from __future__ import annotations

import json
import re
from typing import Optional, Protocol

import httpx
from pydantic import BaseModel

from .config import settings


class ToolCall(BaseModel):
    name: str
    arguments: dict


class LLMResponse(BaseModel):
    content: str = ""
    tool_calls: list[ToolCall] = []


class LLMBackend(Protocol):
    # Contrato que cumplen los tres backends.
    def chat(
        self, messages: list[dict], tools: list[dict], context: Optional[dict] = None
    ) -> LLMResponse: ...


# ──────────────────────────────────────────────────────────────────────────
# MOCK — política scripteada, determinística. Ideal para clase en vivo.
# ──────────────────────────────────────────────────────────────────────────
class MockLLM:
    """
    Simula el razonamiento de un analista con una máquina de estados simple.
    Mira qué tools ya se ejecutaron (en el historial) y decide la próxima.

    Secuencia: reputación de IP -> historial del usuario -> crear ticket -> análisis final.
    Ejercita el ciclo REAL de tool-calling contra el MCP, pero sin depender de un modelo.
    """

    def chat(self, messages, tools, context=None) -> LLMResponse:
        called = _tools_already_called(messages)
        available = {t["function"]["name"] for t in tools}
        ctx = context or {}
        alert = ctx.get("alert", {})
        ip = alert.get("src_ip", "0.0.0.0")
        user = alert.get("user") or "unknown"
        pre_rep = ctx.get("pre_enrichment") or {}

        # Reputación ya vino del worker — saltear.
        skip_rep = bool(pre_rep) or "check_ip_reputation" not in available

        if not skip_rep and "check_ip_reputation" in available and "check_ip_reputation" not in called:
            return LLMResponse(
                tool_calls=[ToolCall(name="check_ip_reputation", arguments={"ip": ip})]
            )

        if "get_user_login_history" in available and "get_user_login_history" not in called:
            return LLMResponse(
                tool_calls=[ToolCall(name="get_user_login_history", arguments={"user": user})]
            )

        if "create_incident_ticket" in available and "create_incident_ticket" not in called:
            rep = pre_rep or _last_reputation(messages)
            severity = "high" if rep.get("blacklisted") else "medium"
            summary = (
                f"SSH brute force desde {ip} contra usuario '{user}'. "
                f"Reputación (pre-IA): score={rep.get('score', '?')}, "
                f"blacklisted={rep.get('blacklisted', '?')}."
            )
            return LLMResponse(
                tool_calls=[
                    ToolCall(
                        name="create_incident_ticket",
                        arguments={"title": f"SSH brute force {ip}", "severity": severity, "summary": summary},
                    )
                ]
            )

        rep = pre_rep or _last_reputation(messages)
        verdict = "maliciosa y en blacklist" if rep.get("blacklisted") else "sospechosa"
        return LLMResponse(
            content=(
                f"Se detectó un ataque de fuerza bruta SSH desde {ip} (reputación {verdict}, "
                f"score {rep.get('score', '?')}/100) contra el usuario '{user}'. "
                f"El contexto de intel ya fue enriquecido por el SOAR antes de este análisis. "
                f"El patrón es consistente con acceso no autorizado. "
                f"Se recomienda bloquear la IP previa aprobación del analista."
            )
        )


# ──────────────────────────────────────────────────────────────────────────
# OLLAMA — modelo local
# ──────────────────────────────────────────────────────────────────────────
class OllamaLLM:
    # Timeout duro: si el modelo tarda demasiado en Mac, caemos a mock
    # para que la demo (y el mail) no se cuelguen.
    TIMEOUT_S = 45

    def chat(self, messages, tools, context=None) -> LLMResponse:
        try:
            import ollama  # import perezoso: solo si de verdad se usa este backend
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

            client = ollama.Client(host=settings.ollama_host, timeout=self.TIMEOUT_S)

            def _call():
                return client.chat(
                    model=settings.ollama_model,
                    messages=messages,
                    tools=tools,
                    options={"temperature": 0.1},
                )

            with ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(_call)
                try:
                    resp = fut.result(timeout=self.TIMEOUT_S)
                except FuturesTimeout as exc:
                    raise TimeoutError(f"Ollama excedió {self.TIMEOUT_S}s") from exc

            msg = resp["message"]
            calls = [
                ToolCall(name=tc["function"]["name"], arguments=tc["function"]["arguments"])
                for tc in msg.get("tool_calls", []) or []
            ]
            return LLMResponse(content=msg.get("content", "") or "", tool_calls=calls)
        except Exception as exc:  # noqa: BLE001
            # Resiliencia: si Ollama no está listo / timeout, no rompemos la demo.
            print(f"[llm] Ollama no disponible ({exc}); usando backend mock temporalmente.", flush=True)
            return MockLLM().chat(messages, tools, context)


# ──────────────────────────────────────────────────────────────────────────
# OPENAI — API compatible
# ──────────────────────────────────────────────────────────────────────────
class OpenAILLM:
    def chat(self, messages, tools, context=None) -> LLMResponse:
        headers = {"Authorization": f"Bearer {settings.openai_api_key}"}
        body = {
            "model": settings.openai_model,
            "messages": messages,
            "tools": tools,
            "temperature": 0.1,
        }
        r = httpx.post(
            f"{settings.openai_base_url}/chat/completions",
            headers=headers,
            json=body,
            timeout=60,
        )
        r.raise_for_status()
        choice = r.json()["choices"][0]["message"]
        calls = [
            ToolCall(name=tc["function"]["name"], arguments=json.loads(tc["function"]["arguments"] or "{}"))
            for tc in choice.get("tool_calls", []) or []
        ]
        return LLMResponse(content=choice.get("content") or "", tool_calls=calls)


def get_backend() -> LLMBackend:
    # Fábrica: elige el backend según la config. Default seguro = mock.
    backend = settings.llm_backend.lower()
    if backend == "ollama":
        return OllamaLLM()
    if backend == "openai":
        return OpenAILLM()
    return MockLLM()


# ── Helpers internos para el MockLLM ──────────────────────────────────────
def _tools_already_called(messages: list[dict]) -> set[str]:
    # Reconstruye qué tools ya se llamaron mirando los mensajes del asistente.
    called: set[str] = set()
    for m in messages:
        for tc in m.get("tool_calls", []) or []:
            fn = tc.get("function", {})
            if fn.get("name"):
                called.add(fn["name"])
    return called


def _last_reputation(messages: list[dict]) -> dict:
    # Busca el último resultado de tool que parezca una reputación de IP.
    for m in reversed(messages):
        if m.get("role") == "tool":
            try:
                data = json.loads(m.get("content", "{}"))
                if "blacklisted" in data or "score" in data:
                    return data
            except (json.JSONDecodeError, TypeError):
                continue
    return {}
