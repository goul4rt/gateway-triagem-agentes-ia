"""Gateway de triagem para acoes de agentes de IA — prova de conceito.

Fluxo: prompt -> planejador (agente simulado) -> triagem -> executar | pendente | negar.
Trilha de auditoria integral: pedido, plano, decisao, aprovador e resultado.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .executor import executar_plano
from .planner import gerar_plano
from .triage import Triagem, carregar_politicas

app = FastAPI(title="Gateway de Triagem — PoC")

POLITICAS = carregar_politicas()
TRIAGEM = Triagem(POLITICAS)
PENDENTES: dict[str, dict] = {}
AUDIT_PATH = Path(__file__).resolve().parent.parent / "reports" / "trilha.jsonl"
AUDIT_PATH.parent.mkdir(exist_ok=True)
TRILHA: list[dict] = []


def _auditar(**campos) -> dict:
    entrada = {"ts": time.time(), **campos}
    TRILHA.append(entrada)
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
    return entrada


class Tarefa(BaseModel):
    usuario: str
    prompt: str
    documentos: list[str] = []


class Decisao(BaseModel):
    aprovador: str
    decisao: str  # "aprovar" | "negar"


@app.post("/agent/task")
def receber_tarefa(t: Tarefa):
    plano = gerar_plano(t.prompt, t.documentos)
    veredito = TRIAGEM.avaliar(plano)

    if veredito["decisao"] == "executar":
        resultados = executar_plano(plano, POLITICAS)
        _auditar(task_id=plano["task_id"], usuario=t.usuario, plano=plano,
                 decisao="executado", motivo=veredito["motivo"], risco=veredito["risco"],
                 aprovador="automatico", resultado=resultados)
        return {"task_id": plano["task_id"], "decisao": "executado", "resultado": resultados}

    if veredito["decisao"] == "pendente":
        PENDENTES[plano["task_id"]] = {"plano": plano, "usuario": t.usuario, "criado": time.time()}
        _auditar(task_id=plano["task_id"], usuario=t.usuario, plano=plano,
                 decisao="pendente", motivo=veredito["motivo"], risco=veredito["risco"],
                 aprovador=None, resultado=None)
        return {"task_id": plano["task_id"], "decisao": "pendente", "motivo": veredito["motivo"]}

    _auditar(task_id=plano["task_id"], usuario=t.usuario, plano=plano,
             decisao="negado", motivo=veredito["motivo"], risco=veredito["risco"],
             aprovador="automatico", resultado=None)
    return {"task_id": plano["task_id"], "decisao": "negado", "motivo": veredito["motivo"]}


@app.get("/approvals")
def listar_pendentes():
    _expirar()
    return [{"task_id": k, "usuario": v["usuario"], "plano": v["plano"]} for k, v in PENDENTES.items()]


@app.post("/approvals/{task_id}/decidir")
def decidir(task_id: str, d: Decisao):
    _expirar()
    item = PENDENTES.pop(task_id, None)
    if item is None:
        raise HTTPException(404, "pendencia_inexistente_ou_expirada")
    if d.decisao == "aprovar" and not TRIAGEM.kill_switch:
        resultados = executar_plano(item["plano"], POLITICAS)
        _auditar(task_id=task_id, usuario=item["usuario"], plano=item["plano"],
                 decisao="executado", motivo="aprovado_por_humano", risco="medio",
                 aprovador=d.aprovador, resultado=resultados)
        return {"task_id": task_id, "decisao": "executado", "resultado": resultados}
    _auditar(task_id=task_id, usuario=item["usuario"], plano=item["plano"],
             decisao="negado", motivo="negado_por_humano_ou_kill_switch", risco="medio",
             aprovador=d.aprovador, resultado=None)
    return {"task_id": task_id, "decisao": "negado"}


@app.post("/admin/killswitch")
def kill_switch(ativo: bool):
    TRIAGEM.kill_switch = ativo
    _auditar(task_id=str(uuid.uuid4()), usuario="admin", plano=None,
             decisao="kill_switch", motivo=f"ativo={ativo}", risco="n/a",
             aprovador="admin", resultado=None)
    return {"kill_switch": ativo}


@app.get("/audit")
def auditoria():
    return TRILHA


def _expirar():
    """Pendencia expirada resolve para negacao, nunca para execucao."""
    ttl = POLITICAS["expiracao_aprovacao_s"]
    agora = time.time()
    for task_id in [k for k, v in PENDENTES.items() if agora - v["criado"] > ttl]:
        item = PENDENTES.pop(task_id)
        _auditar(task_id=task_id, usuario=item["usuario"], plano=item["plano"],
                 decisao="negado", motivo="aprovacao_expirada", risco="medio",
                 aprovador="expiracao", resultado=None)
