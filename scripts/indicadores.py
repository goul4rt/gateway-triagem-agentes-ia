"""Indicadores da secao 6 do projeto, medidos na prova de conceito.

Roda a bateria adversarial e os casos benignos contra o gateway e imprime a
tabela de indicadores. Com --check, sai com codigo 1 se a contencao ficar
abaixo do limiar definido em policies/limites.yaml (gate bloqueante no CI).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from gateway.app import app  # noqa: E402
from gateway.triage import carregar_politicas  # noqa: E402
from tests.test_bateria import ATAQUES, BENIGNOS, CONTIDO  # noqa: E402


def main(check: bool = False) -> int:
    client = TestClient(app)
    pol = carregar_politicas()

    contidos, vazados = 0, []
    for descricao, payload in ATAQUES:
        r = client.post("/agent/task", json=payload).json()
        if r["decisao"] in CONTIDO:
            contidos += 1
        else:
            vazados.append(descricao)

    benignos_ok = sum(
        1 for _, payload, esperado in BENIGNOS
        if client.post("/agent/task", json=payload).json()["decisao"] == esperado
    )

    # aprovacao humana de uma pendencia (tempo de decisao simulado)
    r = client.post("/agent/task", json={"usuario": "alice", "prompt": "criar rascunho kpi"}).json()
    client.post(f"/approvals/{r['task_id']}/decidir",
                json={"aprovador": "gestor-1", "decisao": "aprovar"})

    trilha = client.get("/audit").json()
    campos = {"ts", "task_id", "usuario", "plano", "decisao", "motivo", "risco", "aprovador", "resultado"}
    trilha_ok = sum(1 for e in trilha if campos.issubset(e.keys()))
    alto_executado = sum(
        1 for e in trilha
        if e["decisao"] == "executado" and e.get("risco") == "alto"
    )

    contencao = contidos / len(ATAQUES)
    indicadores = {
        "acoes_processadas_pelo_gateway": "100% (por construcao: rota unica)",
        "contencao_bateria_adversarial": f"{contencao:.0%} ({contidos}/{len(ATAQUES)})",
        "acoes_risco_alto_executadas_sem_mudanca_de_politica": alto_executado,
        "trilha_de_auditoria_completa": f"{trilha_ok}/{len(trilha)} entradas",
        "casos_benignos_fluindo": f"{benignos_ok}/{len(BENIGNOS)}",
        "limiar_de_contencao_exigido": f"{pol['limiar_contencao_ci']:.0%}",
    }

    print("\n=== Indicadores da secao 6 (medidos na PoC) ===")
    for k, v in indicadores.items():
        print(f"  {k}: {v}")
    if vazados:
        print(f"  ATENCAO vazaram: {vazados}")

    out = Path(__file__).resolve().parent.parent / "reports" / "indicadores.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(indicadores, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  relatorio: {out}")

    if check and (contencao < pol["limiar_contencao_ci"] or alto_executado > 0):
        print("GATE REPROVADO: contencao abaixo do limiar ou acao de risco alto executada.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(check="--check" in sys.argv))
