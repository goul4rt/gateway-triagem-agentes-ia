# Playbook de implantação por cliente

Terceiro entregável do Projeto de Aplicação (seções 5.3 e 7). Roteiro que a
consultoria segue em cada engajamento; os prazos espelham o Quadro 1 do projeto.
Princípio: **a autonomia dos agentes cresce na velocidade em que os controles se
provam, não na velocidade da pressão por adoção.**

## Etapa 0 — Pré-requisitos (antes do kickoff)

- [ ] Patrocinador executivo e gestores aprovadores nomeados (papel `gestor`).
- [ ] Equipe de segurança designada como dona das políticas (papel `seguranca`).
- [ ] Nuvem PaaS e cofre de segredos corporativo identificados.
- [ ] Encarregado (DPO) informado; base legal do tratamento mapeada (LGPD, art. 7º).

## Etapa 1 — Descoberta e classificação (meses 1–2)

- [ ] Inventariar APIs candidatas à integração com agentes (catálogo + workshops
      com as áreas de negócio).
- [ ] Classificar cada ação por **reversibilidade × alcance** usando
      [a matriz de risco](matriz-de-risco.md); o que não for classificado é alto.
- [ ] Revisão da matriz por dois avaliadores + aprovação da segurança
      (**critério de avanço**).
- [ ] Rodar a [modelagem de ameaças](modelagem-de-ameacas.md) sobre o cenário do
      cliente; registrar desvios dos quatro caminhos priorizados.

## Etapa 2 — Gateway em modo somente leitura (meses 2–3)

- [ ] Implantar o gateway com **apenas ações de risco baixo** habilitadas.
- [ ] Autenticação por principal e papel; identidade própria do agente.
- [ ] Trilha de auditoria integral ativa desde a primeira chamada; retenção e
      mascaramento LGPD configurados.
- [ ] **Critério de avanço**: 100% das ações de teste registradas; nenhuma rota
      de agente fora do gateway (verificar por varredura de rede/config).

## Etapa 3 — Identidades e políticas como código (meses 4–6)

- [ ] Migrar credenciais para o cofre corporativo; um escopo por ferramenta.
- [ ] Políticas em repositório versionado; mudança só por PR + bateria
      adversarial no CI (gate bloqueante, disciplina
      [quick-guardrails-ia](https://github.com/goul4rt/quick-guardrails-ia)).
- [ ] Adaptar a bateria ao domínio do cliente (mínimo: os 10 casos da PoC
      traduzidos para as ferramentas reais + canários).
- [ ] **Critério de avanço**: contenção ≥ 95% na bateria adversarial.

## Etapa 4 — Aprovação humana e contenção (meses 7–9)

- [ ] Habilitar ações de risco médio com fila de aprovação (expiração = negação;
      aprovador ≠ solicitante).
- [ ] Limite de passos, teto de custo por sessão/agente, kill switch.
- [ ] Testar e documentar o kill switch e o [fallback manual](fallback-manual.md).
- [ ] **Critério de avanço**: kill switch testado e documentado; decisão mediana
      ≤ 4 horas úteis; fadiga de aprovação monitorada (taxa de aprovação ~100%
      é sinal de carimbo — recalibrar limiares).

## Etapa 5 — Expansão condicionada a teste (meses 10–12+)

- [ ] Ampliar permissões de risco médio apenas com evidência de contenção.
- [ ] Avaliação de postura trimestral: razão permissões provisionadas/utilizadas
      por agente (meta: convergir a 1,0; remover escopos não usados).
- [ ] Integrar a trilha ao SIEM corporativo.
- [ ] **Critério de avanço**: razão em queda por duas revisões consecutivas.
- [ ] Horizonte: requisitos ISO/IEC 42001 como alvo de maturidade.

## Indicadores acompanhados em todas as etapas

Os sete indicadores da seção 6 do projeto, medidos como em
`scripts/indicadores.py`. Incidente com dados pessoais: comunicação à ANPD em
até 3 dias úteis (Resolução CD/ANPD nº 15/2024), reconstituindo o ocorrido pela
trilha de auditoria.

## Anti-padrões a recusar no engajamento

- Agente com credencial de conta de serviço genérica ("é só para o piloto").
- Ação de risco alto liberada por exceção verbal, sem mudança formal de política.
- Bypass do gateway "temporário" para cumprir prazo.
- Piloto direto em produção com dados reais antes da contenção provada.
