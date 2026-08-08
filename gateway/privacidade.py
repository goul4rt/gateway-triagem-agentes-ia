"""Mascaramento de dados pessoais e retencao da trilha (Lei 13.709/2018).

Secao 5.1 do projeto: dados pessoais sao mascarados nos planos ANTES do envio
ao provedor de modelo e antes da gravacao na trilha; a trilha tem retencao
definida em policies/limites.yaml. Em producao: DLP corporativo; aqui, regex
para os identificadores mais comuns no contexto brasileiro.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

_PADROES = [
    (re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), "[CPF]"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[EMAIL]"),
    (re.compile(r"\b\d{11}\b"), "[CPF]"),
    (re.compile(r"\(\d{2}\)\s?9?\d{4}-?\d{4}\b"), "[TELEFONE]"),
]


def mascarar(valor):
    """Mascara PII recursivamente em str, dict e list; demais tipos passam."""
    if isinstance(valor, str):
        for padrao, sub in _PADROES:
            valor = padrao.sub(sub, valor)
        return valor
    if isinstance(valor, dict):
        return {k: mascarar(v) for k, v in valor.items()}
    if isinstance(valor, list):
        return [mascarar(v) for v in valor]
    return valor


def aplicar_retencao(path: Path, dias: int, agora: float | None = None) -> int:
    """Remove da trilha entradas mais antigas que a retencao. Retorna removidas."""
    if not path.exists():
        return 0
    limite = (agora or time.time()) - dias * 86400
    linhas = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    mantidas = [l for l in linhas if json.loads(l).get("ts", 0) >= limite]
    removidas = len(linhas) - len(mantidas)
    if removidas:
        path.write_text("".join(f"{l}\n" for l in mantidas), encoding="utf-8")
    return removidas
