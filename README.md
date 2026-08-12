# Gateway de Triagem para Ações de Agentes de IA — Prova de Conceito

Laboratório da PoC descrita na seção 5.3 do Projeto de Aplicação (PUCPR — Arquitetura de
Software, Ciência de Dados e Cybersecurity). Demonstra o padrão **plan-then-execute com
triagem por risco**: o agente (simulado) raciocina, o gateway decide por políticas
determinísticas, o executor age com credencial escopada. O modelo pode ser enganado;
o engano não vira ação.

Guardrails de engenharia seguem a disciplina de
[quick-guardrails-ia](https://github.com/goul4rt/quick-guardrails-ia): gate de CI
bloqueante, canários que provam que a bateria detecta a remoção de cada controle e
[CLAUDE.md](CLAUDE.md) como contrato operacional.

## Arquitetura em 30 segundos

```
requisição autenticada (chave de API → principal com papel e grupos)
   └─ filtro ACL       documento [ACL:grupo] só chega ao modelo se o usuário pode vê-lo
      └─ mascaramento  PII mascarada ANTES do envio ao provedor de modelo (LGPD)
         └─ planner.py agente simulado, deliberadamente ingênuo (vulnerável a LLM01)
              └─ triage.py  políticas em YAML: allowlist, risco, limites, kill switch
                   ├─ risco baixo  → executor.py (credencial escopada do cofre) → APIs simuladas
                   ├─ risco médio  → fila de aprovação (gestor ≠ solicitante; expira = nega)
                   └─ risco alto   → negado por padrão
                        └─ validação de saída: PII mascarada, credencial do cofre redigida
tudo em reports/trilha.jsonl (pedido, plano, decisão, aprovador, agente, resultado),
com retenção definida e PII mascarada; o agente tem identidade própria (agente-poc-1)
```

- `policies/ferramentas.yaml` — allowlist, escopo e risco por ação (reversibilidade × alcance)
- `policies/limites.yaml` — limite de passos, teto de custo, expiração, retenção, limiar do gate
- `policies/identidades.yaml` — principais, papéis (colaborador/gestor/segurança) e grupos
- `tests/test_bateria.py` — 11 ataques (must-block), identidade/segregação/LGPD/ACL, 4 benignos, 2 canários
- `scripts/indicadores.py` — imprime os indicadores da seção 6 do projeto
- `docs/` — [modelagem de ameaças](docs/modelagem-de-ameacas.md) ·
  [matriz de risco](docs/matriz-de-risco.md) · [playbook por cliente](docs/playbook.md) ·
  [kill switch e fallback manual](docs/fallback-manual.md)

## Rodando

```bash
pip install -r requirements.txt
python -m pytest tests/ -q            # bateria completa (18 testes)
python scripts/indicadores.py         # indicadores da seção 6
uvicorn gateway.app:app --reload      # API interativa em http://localhost:8000/docs
```

Na API interativa, autentique com o header `X-Api-Key` (ex.: `chave-alice`
colaborador, `chave-gestor` gestor, `chave-sec` segurança — ver
`policies/identidades.yaml`).

## Resultados medidos (última execução)

| Indicador (seção 6 do projeto) | Resultado |
| --- | --- |
| Ações de agentes processadas pelo gateway | 100% (rota única, por construção) |
| Contenção da bateria adversarial | 100% (11/11), limiar do gate: 95% |
| Ações de risco alto executadas sem mudança de política | 0 |
| Trilha de auditoria completa | 100% das entradas |
| Casos benignos fluindo | 4/4 |
| Tempo mediano de decisão humana | medido pela trilha (ms em laboratório; meta real: ≤ 4h úteis) |
| Razão permissões provisionadas/utilizadas | 3,0 (6/2) — meta: convergir a 1,0 em revisões trimestrais |
| Kill switch e fallback manual | testados; roteiro trimestral em [docs/fallback-manual.md](docs/fallback-manual.md) |

## O que a bateria cobre

Injeção direta e indireta de prompt (LLM01), exfiltração por ferramenta legítima
(LLM02/LLM06), ferramenta fora da allowlist, parâmetro destrutivo em ferramenta de
leitura, limite de passos (loop), teto de custo (LLM10), ação irreversível,
escalação de permissão, kill switch fail-closed, credencial fora de escopo recusada
pela própria API, acesso sem autenticação, papel insuficiente, auto-aprovação
(segregação de funções), documento com ACL restrita chegando ao modelo,
PII em claro na trilha e credencial do cofre vazando na saída. Falso positivo
coberto no must-pass: nome contendo token proibido ("Wallace") não é negado.

## Escopo e limites

PoC de laboratório, sem dados reais e sem LLM pago: o planejador é simulado e
deliberadamente ingênuo porque a tese está na contenção pelo gateway, não na
robustez do modelo. Limites declarados:

- **Estado em memória**: a fila de pendências fica no processo (a trilha é
  arquivo, fonte única); em produção, fila gerenciada + armazenamento de objetos
  para manter a escalabilidade horizontal prometida na seção 5.1 do projeto.
- **Autenticação simulada**: chaves estáticas no lugar do provedor de identidade
  corporativo (OIDC) e do cofre real.
- **Mascaramento por regex**: em produção, DLP corporativo.

Evoluções naturais: OPA/Rego no lugar do YAML, planejador com LLM real atrás do
mesmo gateway e bateria estendida com promptfoo/garak.

Licença MIT.
