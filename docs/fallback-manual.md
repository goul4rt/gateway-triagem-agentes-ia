# Kill switch e fallback manual — procedimento e teste trimestral

Mecanismos de contenção da seção 5.1 e mitigação de "falso senso de segurança"
da seção 5.2 do Projeto de Aplicação. Indicador da seção 6: **executado e
documentado a cada trimestre**.

## Kill switch

- **O que faz**: `POST /admin/killswitch?ativo=true` (papel `seguranca`). Todo
  plano novo é negado (`kill_switch_ativo`) e pendências aprovadas não executam.
  Fail-closed: a falha do gateway também nega por padrão.
- **Quando acionar**: suspeita de manipulação de agente, vazamento de dados,
  consumo anômalo ou a pedido do encarregado/segurança.
- **Evidência automatizada**: `test_kill_switch_fail_closed` na bateria (CI).

## Fallback manual

Com os agentes parados, a operação continua pelos canais que existiam antes da
adoção — o gateway media agentes, não substitui os sistemas:

1. Colaboradores executam as tarefas diretamente nos sistemas de origem
   (mesmas APIs, via interfaces oficiais, com suas credenciais humanas).
2. Pendências da fila de aprovação são tratadas fora do gateway ou aguardam;
   pendência expirada resolve para negação, nunca para execução.
3. A equipe de segurança preserva `reports/trilha.jsonl` (evidência para a
   comunicação à ANPD em até 3 dias úteis, se houver dados pessoais afetados).

## Roteiro do teste trimestral

| Passo | Ação | Resultado esperado |
|---|---|---|
| 1 | Ativar o kill switch | Resposta `{"kill_switch": true}`; entrada na trilha |
| 2 | Submeter tarefa de risco baixo | `negado`, motivo `kill_switch_ativo` |
| 3 | Aprovar uma pendência existente | `negado` (aprovação não executa sob kill switch) |
| 4 | Executar uma tarefa representativa pelo canal manual | Tarefa concluída fora do gateway |
| 5 | Desativar o kill switch | Tarefa de risco baixo volta a executar |
| 6 | Registrar data, executor e resultados neste arquivo | Linha nova no histórico abaixo |

Passos 1–3 e 5 são cobertos de forma contínua pela bateria no CI; o teste
trimestral acrescenta o passo manual (4) e o registro humano (6).

## Histórico de execuções

| Data | Executor | Resultado | Observações |
|---|---|---|---|
| 2026-08-12 | equipe da PoC | OK (bateria + roteiro em laboratório) | primeira execução, ambiente de laboratório |
