"""A trilha e persistida em arquivo (fonte unica); a bateria mede uma execucao
limpa, entao zera a trilha do laboratorio no inicio da sessao de testes."""
from gateway.app import AUDIT_PATH

AUDIT_PATH.write_text("", encoding="utf-8")
