"""Motor de triagem: componente deterministico que decide sobre planos.

Regras (secao 5.1 do projeto):
- ferramenta fora da allowlist -> risco alto (negar por padrao);
- tokens destrutivos em parametros -> negacao no nivel do conector;
- limite de passos e teto de custo -> negacao (contencao);
- kill switch ativo -> negacao (fail-closed);
- risco do plano = maior risco entre os passos;
- baixo executa, medio pende, alto nega.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

POL_DIR = Path(__file__).resolve().parent.parent / "policies"

ORDEM_RISCO = {"baixo": 0, "medio": 1, "alto": 2}


def carregar_politicas() -> dict:
    ferramentas = yaml.safe_load((POL_DIR / "ferramentas.yaml").read_text(encoding="utf-8"))
    limites = yaml.safe_load((POL_DIR / "limites.yaml").read_text(encoding="utf-8"))
    return {**ferramentas, **limites}


class Triagem:
    def __init__(self, politicas: dict | None = None):
        self.pol = politicas or carregar_politicas()
        self.kill_switch = False

    # ---- decisao ----
    def avaliar(self, plano: dict) -> dict:
        """Retorna {"decisao": "executar"|"pendente"|"negar", "motivo": str, "risco": str}."""
        if self.kill_switch:
            return self._nega("kill_switch_ativo")

        passos = plano.get("passos", [])
        if not passos:
            return self._nega("plano_vazio")
        if len(passos) > self.pol["limite_de_passos"]:
            return self._nega("limite_de_passos_excedido")

        custo, pior = 0, "baixo"
        for passo in passos:
            nome = passo.get("ferramenta", "")
            spec = self.pol["ferramentas"].get(nome)
            if spec is None:
                return self._nega(f"ferramenta_desconhecida:{nome}")
            if self._parametros_proibidos(passo.get("parametros", {})):
                return self._nega(f"parametro_proibido:{nome}")
            custo += spec["custo"] + int(passo.get("parametros", {}).get("custo_extra", 0))
            if ORDEM_RISCO[spec["risco"]] > ORDEM_RISCO[pior]:
                pior = spec["risco"]

        if custo > self.pol["teto_de_custo"]:
            return self._nega("teto_de_custo_excedido", risco=pior)
        if pior == "alto":
            return self._nega("risco_alto_bloqueado_por_padrao", risco=pior)
        if pior == "medio":
            return {"decisao": "pendente", "motivo": "aprovacao_humana_requerida", "risco": pior}
        return {"decisao": "executar", "motivo": "risco_baixo", "risco": pior}

    # ---- auxiliares ----
    def _parametros_proibidos(self, params: dict) -> bool:
        blob = " ".join(str(v).lower() for v in params.values())
        # fronteira de palavra so onde a borda do token e alfanumerica:
        # "all" nao nega "Wallace" (falso positivo = fadiga de aprovacao, 5.2),
        # mas "*" e "--" colados a texto ("123*", "x--force") continuam negados
        return any(re.search(self._regex_token(tok), blob)
                   for tok in self.pol["tokens_proibidos_em_parametros"])

    @staticmethod
    def _regex_token(tok: str) -> str:
        inicio = r"(?<!\w)" if tok[0].isalnum() else ""
        fim = r"(?!\w)" if tok[-1].isalnum() else ""
        return inicio + re.escape(tok) + fim

    @staticmethod
    def _nega(motivo: str, risco: str = "alto") -> dict:
        return {"decisao": "negar", "motivo": motivo, "risco": risco}
