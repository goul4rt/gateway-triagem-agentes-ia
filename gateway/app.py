"""Gateway de triagem para acoes de agentes de IA — prova de conceito.

Fluxo: prompt -> filtro ACL de documentos -> mascaramento LGPD -> planejador
(agente simulado) -> triagem -> executar | pendente | negar -> validacao de saida.
Trilha de auditoria integral: pedido, plano, decisao, aprovador, agente e resultado.

Identidade e papeis (NIST SP 800-207): toda rota exige chave de API mapeada em
policies/identidades.yaml; o agente age com identidade propria, registrada na
trilha, distinta do usuario que o acionou.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .executor import executar_plano, valores_de_credencial
from .planner import gerar_plano
from .privacidade import aplicar_retencao, mascarar
from .triage import POL_DIR, Triagem, carregar_politicas

app = FastAPI(title="Gateway de Triagem — PoC")

POLITICAS = carregar_politicas()
IDENT = yaml.safe_load((POL_DIR / "identidades.yaml").read_text(encoding="utf-8"))
AGENTE = IDENT["agente"]["nome"]
TRIAGEM = Triagem(POLITICAS)
PENDENTES: dict[str, dict] = {}  # ponytail: estado em memoria, limite de laboratorio
AUDIT_PATH = Path(__file__).resolve().parent.parent / "reports" / "trilha.jsonl"
AUDIT_PATH.parent.mkdir(exist_ok=True)

# LGPD: retencao aplicada no startup (secao 5.1 do projeto)
aplicar_retencao(AUDIT_PATH, POLITICAS["retencao_trilha_dias"])


# ---- autenticacao e papeis ----
def principal(x_api_key: str | None = Header(default=None)) -> dict:
    p = IDENT["principais"].get(x_api_key or "")
    if p is None:
        raise HTTPException(401, "nao_autenticado")
    return p


def exige_papel(*papeis: str):
    def dep(p: dict = Depends(principal)) -> dict:
        if p["papel"] not in papeis:
            raise HTTPException(403, f"papel_insuficiente:{p['papel']}")
        return p
    return dep


# ---- auditoria ----
# fonte unica: o arquivo (a copia em memoria duplicava a trilha e ignorava a retencao)
def _auditar(**campos) -> dict:
    # mascaramento LGPD antes da gravacao: PII nao persiste em claro
    entrada = mascarar({"ts": time.time(), "agente": AGENTE, **campos})
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
    return entrada


def _ler_trilha() -> list[dict]:
    if not AUDIT_PATH.exists():
        return []
    return [json.loads(l) for l in AUDIT_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]


# ---- controles de dados ----
_ACL = re.compile(r"\[ACL:(\w+)\]")


def _filtrar_documentos_acl(documentos: list[str], p: dict) -> tuple[list[str], int]:
    """Preserva as permissoes de origem na recuperacao (3o caminho de ataque):
    documento marcado [ACL:grupo] so chega ao modelo se o usuario pertence a
    TODOS os grupos marcados — com varias tags, a mais restritiva vence."""
    visiveis = []
    for doc in documentos:
        if any(g not in p["grupos"] for g in _ACL.findall(doc)):
            continue
        visiveis.append(doc)
    return visiveis, len(documentos) - len(visiveis)


def _validar_saida(resultados: list[dict]) -> list[dict]:
    """Validacao tambem na saida (mitigacao da secao 5.2): mascara PII e redige
    qualquer credencial do cofre que vaze para o resultado."""
    blob = json.dumps(resultados, ensure_ascii=False)
    for segredo in valores_de_credencial():
        blob = blob.replace(segredo, "[CREDENCIAL_REDIGIDA]")
    return mascarar(json.loads(blob))


# ---- rotas ----
class Tarefa(BaseModel):
    prompt: str
    documentos: list[str] = []


class Decisao(BaseModel):
    decisao: str  # "aprovar" | "negar"


@app.post("/agent/task")
def receber_tarefa(t: Tarefa, p: dict = Depends(exige_papel("colaborador", "gestor", "seguranca"))):
    docs, filtrados = _filtrar_documentos_acl(t.documentos, p)
    # mascaramento ANTES do envio ao provedor de modelo (planejador simulado)
    plano = gerar_plano(mascarar(t.prompt), [mascarar(d) for d in docs])
    veredito = TRIAGEM.avaliar(plano)

    base = dict(task_id=plano["task_id"], usuario=p["nome"], pedido=t.prompt, plano=plano,
                motivo=veredito["motivo"], risco=veredito["risco"], docs_filtrados_acl=filtrados)

    if veredito["decisao"] == "executar":
        resultados = _validar_saida(executar_plano(plano, POLITICAS))
        _auditar(**base, decisao="executado", aprovador="automatico", resultado=resultados)
        return {"task_id": plano["task_id"], "decisao": "executado", "resultado": resultados}

    if veredito["decisao"] == "pendente":
        PENDENTES[plano["task_id"]] = {"plano": plano, "usuario": p["nome"], "criado": time.time()}
        _auditar(**base, decisao="pendente", aprovador=None, resultado=None)
        return {"task_id": plano["task_id"], "decisao": "pendente", "motivo": veredito["motivo"]}

    _auditar(**base, decisao="negado", aprovador="automatico", resultado=None)
    return {"task_id": plano["task_id"], "decisao": "negado", "motivo": veredito["motivo"]}


@app.get("/approvals")
def listar_pendentes(p: dict = Depends(exige_papel("gestor", "seguranca"))):
    _expirar()
    return [{"task_id": k, "usuario": v["usuario"], "plano": v["plano"]} for k, v in PENDENTES.items()]


@app.post("/approvals/{task_id}/decidir")
def decidir(task_id: str, d: Decisao, p: dict = Depends(exige_papel("gestor", "seguranca"))):
    _expirar()
    item = PENDENTES.get(task_id)
    if item is None:
        raise HTTPException(404, "pendencia_inexistente_ou_expirada")
    if item["usuario"] == p["nome"]:
        raise HTTPException(403, "segregacao_de_funcoes:aprovador_nao_pode_ser_o_solicitante")
    PENDENTES.pop(task_id)
    base = dict(task_id=task_id, usuario=item["usuario"], plano=item["plano"],
                risco="medio", aprovador=p["nome"])
    if d.decisao == "aprovar" and not TRIAGEM.kill_switch:
        resultados = _validar_saida(executar_plano(item["plano"], POLITICAS))
        _auditar(**base, decisao="executado", motivo="aprovado_por_humano", resultado=resultados)
        return {"task_id": task_id, "decisao": "executado", "resultado": resultados}
    _auditar(**base, decisao="negado", motivo="negado_por_humano_ou_kill_switch", resultado=None)
    return {"task_id": task_id, "decisao": "negado"}


@app.post("/admin/killswitch")
def kill_switch(ativo: bool, p: dict = Depends(exige_papel("seguranca"))):
    TRIAGEM.kill_switch = ativo
    _auditar(task_id=str(uuid.uuid4()), usuario=p["nome"], plano=None,
             decisao="kill_switch", motivo=f"ativo={ativo}", risco="n/a",
             aprovador=p["nome"], resultado=None)
    return {"kill_switch": ativo}


@app.get("/audit")
def auditoria(p: dict = Depends(exige_papel("seguranca"))):
    return _ler_trilha()


def _expirar():
    """Pendencia expirada resolve para negacao, nunca para execucao."""
    ttl = POLITICAS["expiracao_aprovacao_s"]
    agora = time.time()
    for task_id in [k for k, v in PENDENTES.items() if agora - v["criado"] > ttl]:
        item = PENDENTES.pop(task_id)
        _auditar(task_id=task_id, usuario=item["usuario"], plano=item["plano"],
                 decisao="negado", motivo="aprovacao_expirada", risco="medio",
                 aprovador="expiracao", resultado=None)
