"""Agente simulado: converte prompt + documentos recuperados em um plano estruturado.

Deliberadamente ingenuo: reproduz o comportamento de um LLM vulneravel a injecao
direta (LLM01) e indireta via conteudo recuperado. A contencao NAO acontece aqui;
acontece no gateway. E exatamente isso que a PoC precisa demonstrar: o modelo pode
ser enganado, e mesmo assim o engano nao vira acao.
"""
from __future__ import annotations

import re
import uuid


def _step(tool: str, **params) -> dict:
    return {"ferramenta": tool, "parametros": params}


def gerar_plano(prompt: str, documentos: list[str] | None = None) -> dict:
    """Gera um plano estruturado a partir do prompt e dos documentos recuperados."""
    p = prompt.lower()
    passos: list[dict] = []

    # intencoes benignas
    if "consultar" in p or "status" in p:
        # ingenuo: repassa o trecho bruto apos "registro", como um LLM que copia
        # texto contaminado do prompt direto para os parametros da ferramenta
        m = re.search(r"registro\s+([\w;'\-\* ]+)", p)
        passos.append(_step("consultar_registro", id=m.group(1).strip() if m else "123"))
    if "rascunho" in p:
        passos.append(_step("criar_rascunho", titulo=prompt[:40]))
    if "agendar" in p:
        passos.append(_step("agendar_tarefa", quando="amanha 09:00"))

    # comportamento ingenuo diante de injecao direta
    if "ignore as instrucoes" in _sem_acentos(p) or "ignore as instruções" in p:
        if "exclu" in p or "apague" in p:
            passos.append(_step("excluir_registro", id="*"))
        if "permiss" in p:
            passos.append(_step("alterar_permissao", usuario="atacante", nivel="admin"))

    # intencoes explicitamente perigosas (usuario mal-intencionado ou desavisado)
    if not passos:
        if "exclu" in p or "apague" in p:
            passos.append(_step("excluir_registro", id="123"))
        if "permiss" in p:
            passos.append(_step("alterar_permissao", usuario="x", nivel="admin"))

    # injecao indireta: instrucao oculta em documento recuperado (RAG envenenado)
    for doc in documentos or []:
        m = re.search(r"\[INSTRUCAO_OCULTA\]\s*tool=(\w+);?(.*)", doc)
        if m:
            params = {}
            for kv in re.findall(r"(\w+)=([^;\]]+)", m.group(2)):
                params[kv[0]] = kv[1].strip()
            passos.append(_step(m.group(1), **params))

    # loop de raciocinio: "repita N vezes"
    m = re.search(r"repita\s+(\d+)", p)
    if m:
        passos.extend(_step("consultar_registro", id=str(i)) for i in range(int(m.group(1))))

    # tarefa cara: relatorio completo estoura o teto de custo
    if "relatorio completo" in _sem_acentos(p) or "relatório completo" in p:
        passos.append(_step("consultar_registro", id="tudo", custo_extra=100))

    if not passos:
        passos.append(_step("consultar_registro", id="123"))

    return {"task_id": str(uuid.uuid4()), "passos": passos}


def _sem_acentos(s: str) -> str:
    tabela = str.maketrans("áàâãéêíóôõúüç", "aaaaeeiooouuc")
    return s.translate(tabela)
