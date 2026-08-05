# Gateway de Triagem para Ações de Agentes de IA — Prova de Conceito

Laboratório da PoC descrita na seção 5.3 do Projeto de Aplicação (PUCPR — Arquitetura de
Software, Ciência de Dados e Cybersecurity). Demonstra o padrão **plan-then-execute com
triagem por risco**: o agente (simulado) raciocina, o gateway decide por políticas
determinísticas, o executor age com credencial escopada. O modelo pode ser enganado;
o engano não vira ação.

Guardrails de engenharia seguem a disciplina de
[quick-guardrails-ia](https://github.com/goul4rt/quick-guardrails-ia): gate de CI
bloqueante e canário que prova que a bateria detecta a remoção do controle.

## Arquitetura em 30 segundos

```
prompt do usuário
   └─ planner.py      agente simulado, deliberadamente ingênuo (vulnerável a LLM01)
        └─ triage.py  políticas em YAML: allowlist, risco, limites, kill switch
             ├─ risco baixo  → executor.py (credencial escopada do cofre) → APIs simuladas
             ├─ risco médio  → fila de aprovação humana (expira = nega)
             └─ risco alto   → negado por padrão
tudo registrado em reports/trilha.jsonl (plano, decisão, aprovador, resultado)
```

- `policies/ferramentas.yaml` — allowlist, escopo e risco por ação (reversibilidade × alcance)
- `policies/limites.yaml` — limite de passos, teto de custo, expiração, limiar do gate
- `tests/test_bateria.py` — 10 ataques (must-block), 3 benignos (must-pass), canário
- `scripts/indicadores.py` — imprime os indicadores da seção 6 do projeto

## Rodando

```bash
pip install -r requirements.txt
python -m pytest tests/ -q            # bateria completa
python scripts/indicadores.py         # indicadores da seção 6
uvicorn gateway.app:app --reload      # API interativa em http://localhost:8000/docs
```

## Resultados medidos (última execução)

| Indicador (seção 6 do projeto) | Resultado |
| --- | --- |
| Ações de agentes processadas pelo gateway | 100% (rota única, por construção) |
| Contenção da bateria adversarial | 100% (10/10), limiar do gate: 95% |
| Ações de risco alto executadas sem mudança de política | 0 |
| Trilha de auditoria completa | 100% das entradas |
| Casos benignos fluindo | 3/3 |

## O que a bateria cobre

Injeção direta e indireta de prompt (LLM01), exfiltração por ferramenta legítima
(LLM02/LLM06), ferramenta fora da allowlist, parâmetro destrutivo em ferramenta de
leitura, limite de passos (loop), teto de custo (LLM10), ação irreversível,
escalação de permissão, kill switch fail-closed e credencial fora de escopo
recusada pela própria API.

## Escopo e limites

PoC de laboratório, sem dados reais e sem LLM pago: o planejador é simulado e
deliberadamente ingênuo porque a tese está na contenção pelo gateway, não na
robustez do modelo. Evoluções naturais: OPA/Rego no lugar do YAML, planejador com
LLM real atrás do mesmo gateway e bateria estendida com promptfoo/garak.

Licença MIT.
