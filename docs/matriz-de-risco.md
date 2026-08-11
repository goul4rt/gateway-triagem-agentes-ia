# Matriz de classificação de risco de ações

Produto da fase 1 do plano de ação (seção 5.1 do Projeto de Aplicação).
Critérios: **reversibilidade** (a ação pode ser desfeita sem perda?) e
**alcance** (quantos registros, sistemas ou pessoas ela afeta?).

Regra de ouro: **operação não classificada = risco alto = negar por padrão.**

## Matriz de decisão

| Reversibilidade \ Alcance | Um registro | Vários registros / um sistema | Amplo (sistemas, pessoas, externo) |
|---|---|---|---|
| **Idempotente (leitura)** | baixo | baixo | médio |
| **Reversível (desfazível sem perda)** | médio | médio | alto |
| **Irreversível** | alto | alto | alto |

## Classificação das ações da PoC (espelho de `policies/ferramentas.yaml`)

| Ação | Reversibilidade | Alcance | Risco | Desfecho | Escopo de credencial |
|---|---|---|---|---|---|
| `consultar_registro` | idempotente | um registro | baixo | executa | `read:registros` |
| `criar_rascunho` | reversível (rascunho descartável) | um registro | médio | aprovação humana | `write:rascunhos` |
| `agendar_tarefa` | reversível (cancelável) | um registro | médio | aprovação humana | `write:agenda` |
| `excluir_registro` | irreversível | um registro | alto | negado por padrão | `delete:registros` |
| `alterar_permissao` | reversível, mas alcance amplo | pessoas/sistemas | alto | negado por padrão | `admin:permissoes` |
| `enviar_email_externo` | irreversível (comunicação externa; canal de exfiltração) | externo | alto | negado por padrão | `send:externo` |

## Processo de manutenção

- Toda mudança nesta matriz é mudança em `policies/ferramentas.yaml`: passa por
  pull request, revisão por **dois avaliadores** e pela bateria adversarial no CI
  (gate bloqueante, limiar em `policies/limites.yaml`).
- Reclassificação obrigatória a cada mudança de API integrada.
- Revisão trimestral do conjunto, junto com a medição de fadiga de aprovação
  (tempo e taxa de aprovação — seção 5.2 do projeto).
