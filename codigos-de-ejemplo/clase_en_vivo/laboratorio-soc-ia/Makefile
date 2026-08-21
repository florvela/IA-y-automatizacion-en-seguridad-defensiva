# Atajos para el laboratorio. Uso: make up / make attack / make logs / make down
.PHONY: up down attack logs test reset ps

up:            ## Levanta TODO el lab (Wazuh + worker + MCP + Ollama + ...)
	docker compose up -d --build

down:          ## Baja el lab
	docker compose down

ps:            ## Estado de los servicios
	docker compose ps

attack:        ## Dispara el ataque de fuerza bruta SSH (exec, no run)
	docker compose exec attacker python brute_force.py

logs:          ## Sigue los logs del SOAR, worker y detector
	docker compose logs -f soar-bridge soc-worker siem-lite

test:          ## Corre las pruebas unitarias offline
	PYTHONPATH=. python3 -m pytest tests/ -q

reset:         ## Baja todo y borra los volúmenes (incidentes, tickets, blocklist)
	docker compose down -v --remove-orphans
