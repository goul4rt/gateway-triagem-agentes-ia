"""Cofre simulado, APIs internas simuladas e executor com identidade propria.

Demonstra privilegio minimo: o executor obtem no cofre a credencial escopada da
ferramenta em tempo de execucao, e cada API interna valida o escopo recebido.
Um token de escopo errado e recusado pela propria API (defesa em profundidade).
"""
from __future__ import annotations

# ---- cofre de segredos (simulado) ----
_CREDENCIAIS = {
    "read:registros": "tok-read-r1",
    "write:rascunhos": "tok-write-d1",
    "write:agenda": "tok-write-a1",
    "delete:registros": "tok-del-r1",
    "admin:permissoes": "tok-adm-p1",
    "send:externo": "tok-send-e1",
}


def obter_credencial(escopo: str) -> str:
    """Credencial escopada, obtida em tempo de execucao; nunca embutida no agente."""
    return _CREDENCIAIS[escopo]


def valores_de_credencial() -> list[str]:
    """Para a validacao de saida: nenhum segredo do cofre pode vazar no resultado."""
    return list(_CREDENCIAIS.values())


# ---- APIs internas simuladas (uma por nivel de risco) ----
_REGISTROS = {"123": {"id": "123", "status": "ativo"}}


def _exige(token: str, escopo: str):
    if _CREDENCIAIS.get(escopo) != token:
        raise PermissionError(f"escopo_invalido:{escopo}")


def api_consultar_registro(token: str, id: str = "123", **_) -> dict:
    _exige(token, "read:registros")
    return {"registro": _REGISTROS.get(id, {"id": id, "status": "nao_encontrado"})}


def api_criar_rascunho(token: str, titulo: str = "", **_) -> dict:
    _exige(token, "write:rascunhos")
    return {"rascunho": {"titulo": titulo, "estado": "criado"}}


def api_agendar_tarefa(token: str, quando: str = "", **_) -> dict:
    _exige(token, "write:agenda")
    return {"agenda": {"quando": quando, "estado": "agendada"}}


def api_excluir_registro(token: str, id: str = "", **_) -> dict:
    _exige(token, "delete:registros")
    _REGISTROS.pop(id, None)
    return {"excluido": id}


_APIS = {
    "consultar_registro": api_consultar_registro,
    "criar_rascunho": api_criar_rascunho,
    "agendar_tarefa": api_agendar_tarefa,
    "excluir_registro": api_excluir_registro,
}


# ---- executor ----
def executar_plano(plano: dict, politicas: dict) -> list[dict]:
    resultados = []
    for passo in plano["passos"]:
        nome = passo["ferramenta"]
        escopo = politicas["ferramentas"][nome]["escopo"]
        token = obter_credencial(escopo)
        fn = _APIS[nome]
        params = {k: v for k, v in passo.get("parametros", {}).items() if k != "custo_extra"}
        resultados.append({"ferramenta": nome, "saida": fn(token, **params)})
    return resultados
