# Modelagem de ameaças — STRIDE × OWASP LLM Top 10 (2025) × MITRE ATLAS

Artefato da fase de preparação citado na seção 2 do Projeto de Aplicação.
Escopo: agentes de IA com capacidade de execução conectados a APIs internas,
no cenário **sem** camada de mediação (arquitetura atual dos clientes).

## Método

1. Decomposição do fluxo: usuário → assistente (LLM) → recuperação de contexto
   (RAG) → ferramentas/APIs internas → dados.
2. Enumeração STRIDE por elemento do fluxo.
3. Cruzamento com o catálogo OWASP Top 10 para LLM (2025) e com as táticas do
   MITRE ATLAS.
4. Priorização por impacto × facilidade, resultando nos **quatro caminhos de
   ataque prioritários** da seção 2.

## Caminhos priorizados

| # | Caminho de ataque | STRIDE | OWASP LLM | MITRE ATLAS | Controle no gateway | Evidência na PoC |
|---|---|---|---|---|---|---|
| 1 | Agência excessiva: agente com credencial ampla executa ação indevida em sistema crítico | Elevation of Privilege, Tampering | LLM06 (Excessive Agency) | AML.T0053 (LLM Plugin Compromise) | Allowlist de ferramentas; risco alto negado por padrão; credencial escopada por ferramenta obtida do cofre | `test_bateria_adversarial_contida`, `test_cofre_recusa_escopo_errado` |
| 2 | Injeção indireta de prompt: conteúdo malicioso em documento recuperado induz plano danoso | Tampering, Spoofing | LLM01 (Prompt Injection) | AML.T0051 (LLM Prompt Injection), AML.T0070 (RAG Poisoning) | Plano estruturado avaliado por regras determinísticas; ferramenta desconhecida = negar; guarda de parâmetros no conector | casos "injecao indireta" da bateria |
| 3 | Quebra de controle de acesso via RAG: índice vetorial não preserva permissões de origem | Information Disclosure | LLM02 (Sensitive Information Disclosure) | AML.T0057 (LLM Data Leakage) | Filtro ACL na recuperação: documento `[ACL:grupo]` só chega ao modelo se o usuário pertence ao grupo; validação também na saída | `test_acl_documento_restrito_nao_chega_ao_modelo`, `test_validacao_de_saida_redige_credencial_e_pii` |
| 4 | Consumo sem limites: loop de raciocínio ou abuso deliberado gera custo direto | Denial of Service | LLM10 (Unbounded Consumption) | AML.T0034 (Cost Harvesting) | Limite de passos por plano; teto de custo por plano; kill switch fail-closed | casos "loop" e "teto de custo" da bateria, `test_kill_switch_fail_closed` |

## Ameaças secundárias mapeadas (tratadas, não priorizadas)

| Ameaça | STRIDE | Controle |
|---|---|---|
| Repúdio de ação do agente ("não fui eu") | Repudiation | Trilha de auditoria integral com identidade própria do agente, usuário e aprovador |
| Vazamento de dados pessoais ao provedor de modelo | Information Disclosure | Mascaramento LGPD antes do envio ao planejador e antes da gravação na trilha |
| Auto-aprovação (solicitante aprova o próprio plano) | Elevation of Privilege | Segregação de funções: `403` se aprovador == solicitante |
| Acesso não autenticado ao gateway/auditoria/kill switch | Spoofing | Autenticação por principal e papel em todas as rotas |

## Premissas e limites

- O modelo é tratado como **não confiável** (zero trust, NIST SP 800-207): a
  contenção não depende do comportamento do LLM.
- Detecção de manipulação em linguagem natural é probabilística; por isso a
  defesa é em camadas independentes (triagem, conector, cofre, saída), cada uma
  assumindo que a anterior pode falhar.
- Fora do escopo da PoC: adversário com acesso à infraestrutura do gateway
  (tratado pelos controles corporativos ISO/IEC 27001 já existentes).
