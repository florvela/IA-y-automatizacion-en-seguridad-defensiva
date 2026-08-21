"""
Configuración central del laboratorio.

# Todo se controla por variables de entorno con prefijo SOC_ (ver .env).
# Un solo lugar para la config = código limpio y fácil de auditar.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ── MCP ───────────────────────────────────────────────────────────
    # URL del servidor MCP (transporte streamable-http).
    mcp_url: str = "http://mcp-server:8080/mcp"

    # ── Backend del LLM ───────────────────────────────────────────────
    # "mock"   -> determinístico, no necesita nada (ideal para la demo en vivo)
    # "ollama" -> modelo local (perfil docker "ollama")
    # "openai" -> API compatible OpenAI (necesita SOC_OPENAI_API_KEY)
    llm_backend: str = "mock"
    ollama_host: str = "http://ollama:11434"
    ollama_model: str = "llama3.2"
    openai_base_url: str = "https://api.openai.com/v1"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    # ── Persistencia ──────────────────────────────────────────────────
    # Carpeta compartida (volumen docker) donde viven incidentes y buzón de mail.
    state_dir: str = "/data/state"

    # ── Notificación por email (runbook en el cuerpo) ─────────────────
    # Vacío smtp_host = no se envía; escribe .eml en /data/state/mailbox (demo offline).
    # Para mail real (ej. Gmail): host + port 587 + starttls + user + app password.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = True
    email_from: str = "soc@lab.local"
    email_to: str = "analyst@lab.local"

    # ── Política de respuesta ─────────────────────────────────────────
    # Por defecto TODA acción bloqueante requiere aprobación humana.
    auto_block_low_risk: bool = False

    # URL pública del dashboard (links en emails al analista).
    dashboard_url: str = "http://localhost:9000"

    # Datos semilla (blacklist, usuarios) para enrichment offline.
    seed_dir: str = "/app/data"

    # Anomaly ML (One-Class SVM tabular). True/False; default = auto si hay .joblib
    anomaly_ml: bool | None = None
    ml_dir: str = ""  # vacío = {seed_dir}/ml

    # Fallback Wazuh → bridge si el worker no responde.
    wazuh_fallback_url: str = "http://soar-bridge:9000/webhook/wazuh"

    model_config = SettingsConfigDict(env_prefix="SOC_", env_file=".env", extra="ignore")


# Instancia única que importan todos los módulos.
settings = Settings()
