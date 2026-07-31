# Plano de ação

Passo a passo sequencial para construir o `iam-governance-lab` do zero até rodar online.
Cada fase tem um objetivo, as tarefas na ordem em que fazem sentido, e um criterio de
"pronto" (definition of done). As fases dependem das anteriores; dá para paralelizar dentro
de uma fase, mas não pular pré-requisito.

Termos técnicos (entitlement, role, SoD, privilege escalation, reachability, joiner/mover/
leaver, recertification) ficam em inglês de propósito: é o vocabulário de IAM/IGA que todo
mundo da área usa.

## Objetivo

Um motor de governança de acesso read-only sobre dados sintéticos multi-conta, com dashboard
web, editor de dados persistido em banco e deploy em container. Tudo auditável: cada finding
tem procedência, cada score tem fórmula escrita, cada decisão de escopo está documentada.

## Pré-requisitos

- Python 3.11+ e `pip`.
- Git.
- Docker (só para empacotar e rodar o container; não é necessário para desenvolver).
- Nada de credencial de nuvem: o lab não fala com IdP nem com AWS reais.

---

## Fase 0: fundação do repositório

Objetivo: um repositório que já roda os quality gates, mesmo vazio de lógica.

1. Criar o layout `src/` (`src/iamgov/`) com `pyproject.toml` (build via `setuptools`,
   `requires-python >= 3.11`, dependências e extras `dev`).
2. Configurar `ruff` (lint + import sort), `mypy` em modo `strict`, e `pytest` (`pythonpath =
   ["src"]`) dentro do `pyproject.toml`.
3. Adicionar `.gitignore` (venv, caches, `*.db`, `out/`) e um `Makefile` com os alvos
   `install`, `lint`, `type`, `test`, `serve`.
4. `git init`, primeiro commit.

Pronto quando: `ruff`, `mypy` e `pytest` rodam sem erro num projeto ainda esqueleto.

## Fase 1: modelo de domínio e integridade

Objetivo: o coração do projeto, os tipos e as regras que impedem dado inválido de existir.

1. Modelar em Pydantic (`model.py`): `Account`, `Entitlement`, `Group`, `Role`, `Identity`,
   `SoDRule`, `Policy`, e o agregado `Dataset`. Modelos `frozen`, `extra="forbid"`.
2. Separar as duas noções de acesso desde já: standing access (grants diretos + grupos) versus
   reachable access (o que se alcança assumindo role). Documentar por que são distintas.
3. Implementar o `model_validator` do `Dataset`: unicidade de ids, integridade referencial
   (nada aponta para id inexistente) e detecção de ciclo em nesting de grupo.
4. `loader.py`: ler os YAML de um diretório e validar em duas fases (shape do Pydantic, depois
   integridade do agregado). Falhar alto no carregamento, nunca produzir finding errado calado.

Pronto quando: dataset inválido levanta erro claro no load; dataset válido vira `Dataset`.

## Fase 2: dataset sintético

Objetivo: dados fictícios realistas que exercitam cada control de propósito.

1. Escrever os YAML em `data/`: 4 contas (management, production, development, security),
   entitlements com privilege levels, grupos com nesting, roles com trust cross-account.
2. Semear casos deliberados: SoD herdado (grupo que aninha ops e approvers), escalonamento
   cross-account (dev que assume role admin em prod), wildcard trust, privilege creep, leaver
   com acesso, identity dormante.
3. `policy.yaml`: `dormancy_days` e as baselines de cada título (joiner).

Pronto quando: o dataset carrega válido e contém pelo menos um exemplo de cada finding.

## Fase 3: engines de análise

Objetivo: transformar o `Dataset` em findings, cada um com procedência.

1. `access.py`: resolução de standing access com fecho transitivo de grupos e procedência
   (grant direto ou a cadeia de grupos que trouxe o entitlement).
2. `sod.py`: detecção de toxic combinations. Uma violação exige match nos dois lados da regra,
   em pelo menos dois entitlements distintos. Reportar procedência e se é herança pura.
3. `reachability.py`: montar o grafo dirigido (NetworkX), computar fecho transitivo, extrair o
   caminho de escalonamento, marcar cross-account. Trust modelado por conta, aresta `assume`
   só existe quando os dois lados concordam.
4. `jml.py`: joiner gaps, privilege creep, orphaned access (leavers), dormancy.
5. `recert.py`: risk score com fórmula documentada, buckets, recomendação, campanhas por
   manager e worklist de revogação.
6. `report.py`: agregação em JSON e render em Markdown.

Pronto quando: existe teste com ground truth para cada engine e o `scan` bate com o esperado.

## Fase 4: testes com ground truth

Objetivo: provar correção, não só ausência de exceção.

1. Fixture pequeno construído em código, com as respostas calculadas à mão, para asserts
   exatos por engine.
2. Testes que travam os números do dataset publicado (mudança no seed passa a ser intencional).
3. Rodar `pytest` no CI em Python 3.11, 3.12 e 3.13.

Pronto quando: a suíte cobre SoD, reachability, JML, recert e integridade, toda verde.

## Fase 5: API e CLI

Objetivo: expor os engines por HTTP e por linha de comando.

1. `cli.py`: `validate`, `scan`, `report`, `serve` (via `argparse`, sem dependência extra).
2. `api.py` (FastAPI): endpoints GET read-only (`/api/metrics`, `/api/sod`, `/api/reachability`,
   `/api/escalation`, `/api/jml`, `/api/recert`, `/api/graph`, `/api/graph/path`).
3. Servir o dashboard estático montado em `/`.

Pronto quando: `iamgov serve` sobe e todos os endpoints respondem 200 com o shape esperado.

## Fase 6: dashboard web

Objetivo: tornar os findings visíveis e o grafo navegável no browser.

1. `web/index.html` + `styles.css` (tema próprio, sem framework de CSS externo).
2. `app.js`: cards e charts (Chart.js), tabelas dinâmicas, e o grafo interativo (Cytoscape.js)
   com destaque do caminho de escalonamento ao escolher target e identity.
3. Libs de frontend via CDN com versão fixada, sem build step.

Pronto quando: abrir no browser mostra os dados vivos e o trace de caminho funciona.

## Fase 7: persistência em banco e restore

Objetivo: estado durável e um demo público que sempre se recupera.

1. `db.py` (SQLAlchemy): uma tabela por kind, campos escalares em coluna e listas/nested em
   coluna JSON. SQLite por padrão, PostgreSQL via `DATABASE_URL`.
2. `store.py`: dataset editável lastreado no banco. Toda edição rebuilda o `Dataset` inteiro e
   revalida antes de gravar, como um único snapshot transacional. Seed automático se o banco
   estiver vazio. `restore_defaults` reconstrói do seed embutido.
3. Endpoints de escrita: upsert, delete, restore. Erro de integridade responde 400.
4. Editor no dashboard: criar/editar/remover com validação ao vivo e recálculo dos findings.

Pronto quando: editar persiste no banco, sobrevive a restart, e o restore volta ao padrão.

## Fase 8: empacotamento e CI/CD

Objetivo: uma imagem que sobe em qualquer lugar e um pipeline que protege a main.

1. `Dockerfile` (usuário não-root, healthcheck, volume `/data`), `.dockerignore`,
   `docker-compose.yml`.
2. CI (GitHub Actions): lint, type, test na matriz de versões, mais build da imagem e
   healthcheck do container.
3. CD: build e publicação da imagem, e deploy no destino (blueprint de plataforma). Detalhe em
   `docs/ci-cd.md`.

Pronto quando: `docker compose up` sobe o app e o pipeline passa verde no push.

## Fase 9: segurança e demo público

Objetivo: expor sem virar um problema.

1. Auth Basic opcional que protege só escrita (`IAMGOV_AUTH_USER`/`IAMGOV_AUTH_PASS`); leitura
   fica aberta para o público validar.
2. Reset periódico opcional (`DEMO_RESET_MINUTES`) para o demo se autocurar.
3. TLS via reverse proxy na frente. Nada de secret no código nem na imagem.

Pronto quando: dá para publicar num DNS com edição aberta e o demo se mantém saudável.

## Fase 10: documentação

Objetivo: quem chega entende o porquê, não só o como.

1. `README.md`: o que é, por que existe, quickstart, deploy.
2. `docs/arquitetura.md`: C4 (contexto, contêiner, componente) e diagramas de sequência.
3. `docs/ci-cd.md`: o ciclo de entrega.
4. Docs por engine e `docs/limitacoes.md` + `docs/modelo-de-ameacas.md` com o escopo honesto.

Pronto quando: um revisor navega do README aos diagramas e aos limites sem pedir contexto.

---

## Ordem de execução resumida

```
Fase 0  ->  Fase 1  ->  Fase 2  ->  Fase 3  ->  Fase 4
                                       |
                                       v
                          Fase 5  ->  Fase 6
                                       |
                                       v
                          Fase 7  ->  Fase 8  ->  Fase 9
                                       |
                                       v
                                    Fase 10 (contínua)
```

A documentação (Fase 10) acompanha o desenvolvimento, não fica para o fim. Cada fase só é
considerada pronta com seus testes e sua doc no lugar.
