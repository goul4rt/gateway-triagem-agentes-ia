# Contrato operacional (disciplina quick-guardrails-ia)

PoC do gateway de triagem de ações de agentes de IA (Projeto de Aplicação PUCPR).
Python 3.12+, FastAPI. Sem dependências novas sem justificativa.

## Regras invariantes

- **Gate bloqueante**: `python -m pytest tests/ -q` e
  `python scripts/indicadores.py --check` devem passar antes de qualquer commit.
- **Políticas só mudam por PR**: `policies/*.yaml` é a fonte de verdade da
  triagem; toda mudança exige a bateria verde e reflexo em
  `docs/matriz-de-risco.md`.
- **Todo controle novo nasce com teste**: um must-block que prova que ele
  bloqueia e, quando couber, um canário que prova que a bateria detecta a
  remoção do controle (`test_canario_*`).
- **Negar por padrão**: ferramenta fora da allowlist, pendência expirada,
  kill switch e falha do gateway resolvem para negação, nunca para execução.
- **LGPD**: nenhum dado pessoal em claro na trilha ou em fixtures; use os
  padrões de `gateway/privacidade.py`.

## Mapa do repositório

| Caminho | Papel |
|---|---|
| `gateway/` | planner (agente simulado), triage (decisão), executor (cofre + APIs), privacidade, app |
| `policies/` | ferramentas (allowlist/risco/escopo), limites, identidades |
| `tests/test_bateria.py` | bateria adversarial + benignos + canários |
| `scripts/indicadores.py` | indicadores da seção 6 do projeto |
| `docs/` | modelagem de ameaças, matriz de risco, playbook, fallback manual |
