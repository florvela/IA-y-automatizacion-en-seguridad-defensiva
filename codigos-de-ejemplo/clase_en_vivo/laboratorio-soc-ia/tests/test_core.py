"""
Pruebas unitarias offline (no necesitan Docker ni el servidor MCP).

# Corren rápido y validan la lógica pura: parseo de Wazuh, regex del SIEM,
# y la máquina de estados del LLM mock. Ejecutar con: pytest -q
"""
import sys
from pathlib import Path

# Permite importar el paquete soc y los servicios sin instalar nada.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from soc.wazuh import alert_from_wazuh  # noqa: E402
from soc.llm import MockLLM  # noqa: E402


def test_wazuh_parser_extrae_ip_y_usuario():
    payload = {
        "id": "abc",
        "rule": {"id": "5712", "description": "SSH brute force", "level": 10},
        "data": {"srcip": "203.0.113.5", "dstuser": "root"},
        "agent": {"name": "victim"},
    }
    alert = alert_from_wazuh(payload)
    assert alert.src_ip == "203.0.113.5"
    assert alert.user == "root"
    assert alert.rule_id == "5712"


def test_wazuh_parser_saca_ip_del_full_log_si_falta():
    payload = {
        "rule": {"id": "5712", "description": "x", "level": 5},
        "data": {},
        "full_log": "Failed password for root from 8.8.4.4 port 22",
    }
    alert = alert_from_wazuh(payload)
    assert alert.src_ip == "8.8.4.4"


def test_siem_lite_regex():
    from services.siem.siem_lite import FAILED_RE

    line = "Aug 18 10:00:00 victim sshd[9]: Failed password for invalid user admin from 172.20.0.66 port 5 ssh2"
    m = FAILED_RE.search(line)
    assert m and m.group("ip") == "172.20.0.66" and m.group("user") == "admin"
    # Una línea de login exitoso NO debe matchear.
    assert FAILED_RE.search("Accepted password for labuser from 10.0.0.2 port 5 ssh2") is None


def test_mock_llm_pide_reputacion_primero():
    tools = [{"function": {"name": n}} for n in ("check_ip_reputation", "get_user_login_history", "create_incident_ticket")]
    resp = MockLLM().chat(messages=[], tools=tools, context={"alert": {"src_ip": "1.2.3.4", "user": "root"}})
    assert resp.tool_calls[0].name == "check_ip_reputation"
    assert resp.tool_calls[0].arguments["ip"] == "1.2.3.4"


def test_mock_llm_salta_reputacion_si_pre_enrichment():
    tools = [{"function": {"name": n}} for n in ("check_ip_reputation", "get_user_login_history", "create_incident_ticket")]
    ctx = {"alert": {"src_ip": "1.2.3.4", "user": "root"}, "pre_enrichment": {"blacklisted": True, "score": 95}}
    resp = MockLLM().chat(messages=[], tools=tools, context=ctx)
    assert resp.tool_calls[0].name == "get_user_login_history"


def test_enrichment_blacklist():
    import os
    os.environ["SOC_SEED_DIR"] = str(ROOT / "data")
    from soc.enrichment import lookup_ip_reputation  # noqa: E402

    rep = lookup_ip_reputation("172.20.0.66")
    assert rep["blacklisted"] is True
    assert rep["score"] >= 90


def test_scoring_brute_force_lab_es_high():
    """Escenario demo: regla 5551 + root + victim + IP blacklisteada → score alto."""
    import os
    os.environ["SOC_SEED_DIR"] = str(ROOT / "data")
    from soc.config import settings
    from soc.models import Alert, Incident, IPReputation
    from soc.scoring import apply_score_to_incident, THRESHOLD_HIGH

    settings.anomaly_ml = False  # sin modelo ML en este test
    settings.seed_dir = str(ROOT / "data")

    alert = Alert(
        id="demo",
        rule_id="5551",
        rule_description="PAM: Multiple failed logins",
        level=10,
        src_ip="172.20.0.66",
        dst_host="victim",
        user="root",
        timestamp="2026-08-20T03:15:00+00:00",  # horario atípico
    )
    inc = Incident(id="demo", alert=alert)
    inc.enrichment.ip_reputation = IPReputation(
        ip="172.20.0.66", blacklisted=True, score=95, sources=["blacklist"], country="RU"
    )
    result = apply_score_to_incident(inc)
    assert result["score"] >= THRESHOLD_HIGH
    assert inc.risk == "high"
    assert inc.proposed_action == "block_ip:172.20.0.66"
    assert "alerta" in result["breakdown"]
    assert "threat_intel" in result["breakdown"]
    assert "anomalia_ml" in result["breakdown"]


def test_scoring_labuser_sin_blacklist_es_bajo_o_medio():
    import os
    os.environ["SOC_SEED_DIR"] = str(ROOT / "data")
    from soc.config import settings
    from soc.models import Alert, Incident, IPReputation
    from soc.scoring import apply_score_to_incident, THRESHOLD_HIGH

    settings.anomaly_ml = False
    settings.seed_dir = str(ROOT / "data")

    alert = Alert(
        id="low",
        rule_id="5500",
        rule_description="login ok",
        level=3,
        src_ip="10.0.0.5",
        dst_host="unknown",
        user="labuser",
        timestamp="2026-08-20T14:00:00+00:00",
    )
    inc = Incident(id="low", alert=alert)
    inc.enrichment.ip_reputation = IPReputation(
        ip="10.0.0.5", blacklisted=False, score=5, sources=["blacklist-interna"], country="—"
    )
    result = apply_score_to_incident(inc)
    assert result["score"] < THRESHOLD_HIGH
    assert inc.risk in ("low", "medium")


def test_alert_to_text_template():
    from soc.anomaly import alert_to_text, features_to_text, features_to_vector, VECTOR_DIM
    from soc.models import Alert, Incident, IPReputation

    alert = Alert(
        id="t",
        rule_id="5551",
        rule_description="bf",
        level=10,
        src_ip="172.20.0.66",
        dst_host="victim",
        user="root",
        timestamp="2026-08-20T03:15:00+00:00",
    )
    inc = Incident(id="t", alert=alert)
    inc.enrichment.ip_reputation = IPReputation(
        ip="172.20.0.66", blacklisted=True, score=95, sources=["blacklist"], country="RU"
    )
    text = alert_to_text(inc)
    assert text == (
        "user=root host=victim src_ip=172.20.0.66 hour=3 country=RU"
    )
    assert "rule=" not in text
    vec = features_to_vector(
        {"user": "u", "host": "h", "src_ip": "1.1.1.1", "hour": 12, "country": "AR"}
    )
    assert len(vec) == VECTOR_DIM
    assert features_to_text(
        {"user": "u", "host": "h", "src_ip": "1.1.1.1", "hour": 12, "country": "AR"}
    ).startswith("user=u")


def test_anomalia_ml_scoring_con_forest_mockeado(monkeypatch):
    """Scoring con One-Class SVM mock — sin sklearn pesado en CI."""
    from soc.config import settings
    from soc.models import Alert, Incident, IPReputation
    from soc import anomaly
    from soc.scoring import compute_risk_score

    settings.anomaly_ml = True
    settings.seed_dir = str(ROOT / "data")

    class FakeModel:
        def predict(self, X):
            return [-1]

        def decision_function(self, X):
            return [-0.8]

    anomaly._model = FakeModel()
    anomaly._load_attempted = True
    anomaly._meta = {"feature_version": 3, "algorithm": "OneClassSVM"}

    monkeypatch.setattr(anomaly, "anomaly_enabled", lambda: True)
    monkeypatch.setattr(anomaly, "_load_models", lambda: True)

    alert = Alert(
        id="ml",
        rule_id="5551",
        rule_description="bf",
        level=10,
        src_ip="172.20.0.66",
        dst_host="victim",
        user="root",
        timestamp="2026-08-20T03:00:00+00:00",
    )
    inc = Incident(id="ml", alert=alert)
    inc.enrichment.ip_reputation = IPReputation(
        ip="172.20.0.66", blacklisted=True, score=95, sources=["blacklist"], country="RU"
    )
    result = compute_risk_score(inc)
    assert result["breakdown"]["anomalia_ml"]["points"] >= 18
    assert "OUTLIER" in result["breakdown"]["anomalia_ml"]["reasons"][0]

    anomaly._model = None
    anomaly._load_attempted = False
    settings.anomaly_ml = False


def test_report_sections():
    from soc.models import Alert, Incident, IPReputation
    from soc.pre_enrichment import format_pre_ia_context
    from soc.reporting import build_report

    alert = Alert(id="t1", rule_id="5712", rule_description="bf", level=10, src_ip="1.2.3.4", user="root")
    inc = Incident(id="t1", alert=alert)
    inc.enrichment.ip_reputation = IPReputation(ip="1.2.3.4", blacklisted=True, score=95, sources=["test"])
    inc.pre_ia_context = format_pre_ia_context(inc)
    inc.analysis = "Resolución de prueba."
    inc.risk_score = 88
    md = build_report(inc)
    assert "DATA RECIBIDA EN EL TICKET" in md
    assert "RESOLUCION" in md
    assert "Resolución de prueba" in md
    assert "score 88/100" in md
