# iam-governance-lab entrypoints de desenvolvimento
# Nota Windows: use `py -3 -m ...` se `make` não existir; os alvos espelham os passos do CI.

PY ?= python

.PHONY: help install lint type test check serve scan report clean

help:
	@echo "install  instala o pacote + deps de dev no ambiente ativo"
	@echo "lint     roda o ruff"
	@echo "type     roda o mypy (strict)"
	@echo "test     roda o pytest"
	@echo "check    lint + type + test (o que o CI roda)"
	@echo "serve    sobe a API + dashboard em http://127.0.0.1:8000"
	@echo "scan     roda o scan de governança sobre data/ e imprime um resumo"
	@echo "report   gera os reports Markdown + JSON em out/"

install:
	$(PY) -m pip install -e ".[dev]"

lint:
	$(PY) -m ruff check src tests

type:
	$(PY) -m mypy

test:
	$(PY) -m pytest

check: lint type test

serve:
	$(PY) -m uvicorn iamgov.api:app --host 127.0.0.1 --port 8000 --reload

scan:
	$(PY) -m iamgov.cli scan --data data

report:
	$(PY) -m iamgov.cli report --data data --out out

clean:
	$(PY) -c "import shutil,glob,os; [shutil.rmtree(p,ignore_errors=True) for p in ['.pytest_cache','.mypy_cache','.ruff_cache','out','build','dist']]"
