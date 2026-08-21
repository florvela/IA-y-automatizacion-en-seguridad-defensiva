# Diagrama de arquitectura (lab actual)

Flujo: **ataque SSH → Wazuh → soc-worker → soar-bridge → (IA investiga) → HITL → blocklist**.

Punto clave: el **LLM no ejecuta el bloqueo**. El botón del dashboard llama a MCP en código (`approved=True`).

```mermaid
flowchart TB
  subgraph DET["Detección"]
    A["attacker<br/>SSH brute force<br/>172.20.0.66"]
    V["victim sshd"]
    W["Wazuh"]
    WK["soc-worker<br/>enrichment IP"]
  end

  subgraph SOAR["soar-bridge :9000"]
    PB["playbook"]
    AG["agente + LLM<br/>solo investiga"]
    SC["scoring<br/>propone block_ip:IP<br/>awaiting_approval"]
  end

  subgraph MCP["mcp-server"]
    SAFE["tools seguras<br/>historial · ticket<br/>+ resource · prompt"]
    BLOCK["tool block_ip<br/>exige approved=True"]
  end

  H(("Analista<br/>dashboard"))
  MAIL["email + ticket"]
  BL["/data/state/blocklist"]

  A --> V --> W --> WK --> PB
  PB --> AG
  AG <-->|"tool-calling<br/>(el LLM elige)"| SAFE
  AG -->|"NO ve block_ip"| BLOCK
  PB --> SC
  SC --> MAIL
  MAIL --> H
  SC -->|"muestra incidente"| H

  H -->|"botón Aprobar<br/>POST /approve"| CODE["approval.approve()<br/>Python determinista"]
  CODE -->|"call_tool block_ip<br/>approved=True<br/>(SIN LLM)"| BLOCK
  BLOCK --> BL
```

## Dos caminos distintos (para la clase)

| Camino | Quién decide | Qué hace |
|--------|----------------|----------|
| **Investigación** | LLM (tool-calling) | Lee historial, crea ticket, escribe RESOLUCION |
| **Bloqueo** | Analista + código | Botón → `approval.approve()` → `block_ip(approved=True)` |

```text
LLM  ──tools seguras──► MCP
Analista ──botón──► approval.py ──block_ip(approved=True)──► MCP ──► blocklist
```

## Etapas en una frase

1. Ataque SSH real → logs → Wazuh.
2. Worker enriquece IP y manda al bridge.
3. Agente: prompt/resource MCP + tools seguras; **sin** `block_ip` en el catálogo del LLM.
4. Scoring propone acción y deja `awaiting_approval`.
5. Analista aprueba en `:9000` → código llama MCP → blocklist.

## URLs

| Qué | Dónde |
|-----|--------|
| Dashboard | http://localhost:9000 |
| Wazuh | https://localhost:443 |
