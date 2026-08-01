# Arquitetura

Os diagramas seguem o modelo C4 (contexto, contêiner, componente) e diagramas de sequência
para os fluxos principais. Todos estão em Mermaid, versionados junto do código, então mudam
com ele em vez de virar imagem obsoleta.

Princípio que atravessa tudo: a análise é read-only sobre uma fonte de verdade. No lab essa
fonte é um dataset sintético em banco, editável para autoria de cenários; num deployment real,
seria um export read-only de um IdP. O motor nunca escreve no store de identidades real.

## C4 nível 1: contexto

Quem usa o sistema e o que ele é, sem detalhe interno.

```mermaid
C4Context
    title Contexto do iam-governance-lab

    Person(analista, "Analista de acesso", "Revisa findings de SoD, escalonamento e ciclo JML; decide revogações")
    Person(visitante, "Visitante do demo", "Explora o dashboard e edita cenários")
    Person(owner, "Owner / SRE", "Opera o deploy e define auth e reset")

    System(lab, "iam-governance-lab", "Motor de governança de acesso read-only com dashboard e editor de cenários sobre dados sintéticos")

    Rel(analista, lab, "Analisa findings", "HTTPS")
    Rel(visitante, lab, "Explora e edita cenários", "HTTPS")
    Rel(owner, lab, "Configura e opera", "env vars / container")

    UpdateLayoutConfig($c4ShapeInRow="2", $c4BoundaryInRow="1")
```

## C4 nível 2: contêiner

As peças executáveis e como conversam.

```mermaid
C4Container
    title Conteineres do iam-governance-lab

    Person(user, "Usuário", "Analista ou visitante")

    System_Boundary(sb, "iam-governance-lab") {
        Container(spa, "Dashboard", "HTML, CSS, JS (Cytoscape.js, Chart.js via CDN)", "Renderiza cards, charts, tabelas e o grafo interativo de escalonamento")
        Container(api, "API", "Python, FastAPI, Uvicorn", "Expõe os engines por HTTP e serve o dashboard estático")
        ContainerDb(db, "Banco de dados", "SQLite (padrão) ou PostgreSQL", "Guarda o dataset editável do lab")
        Container(seed, "Seed", "YAML embutido na imagem", "Dataset padrão; semeia banco vazio e lastreia o restore")
    }

    Rel(user, spa, "Acessa", "HTTPS")
    Rel(spa, api, "Consome", "JSON sobre HTTP")
    Rel(api, db, "Lê e grava snapshot", "SQLAlchemy")
    Rel(api, seed, "Semeia se vazio / restaura", "leitura de YAML")

    UpdateLayoutConfig($c4ShapeInRow="2", $c4BoundaryInRow="1")
```

## C4 nível 3: componentes da API

O interior do contêiner de API. As setas são dependências de uso.

```mermaid
C4Component
    title Componentes da API

    Container(spa, "Dashboard", "JS")
    ContainerDb(db, "Banco de dados", "SQLite/PostgreSQL")

    Container_Boundary(api, "API FastAPI") {
        Component(routes, "routes (api.py)", "FastAPI", "Endpoints read-only e de edição; auth de escrita; lifespan")
        Component(store, "DataStore (store.py)", "Python", "Dataset editável; valida e grava snapshot; restore")
        Component(dbc, "db (db.py)", "SQLAlchemy", "Tabela por kind; seed transacional; to_payload")
        Component(loader, "loader (loader.py)", "Python", "Lê YAML e valida em duas fases")
        Component(model, "model (model.py)", "Pydantic", "Dataset tipado e integridade referencial")
        Component(access, "access (access.py)", "Python", "Standing access com procedência: RBAC (grupo) e ABAC (atributo)")
        Component(sod, "sod (sod.py)", "Python", "Detecção de toxic combinations")
        Component(reach, "reachability (reachability.py)", "NetworkX", "Grafo, fecho transitivo, caminho de escalonamento")
        Component(jml, "jml (jml.py)", "Python", "Joiner/mover/leaver, privilege creep, dormancy")
        Component(recert, "recert (recert.py)", "Python", "Risk score, campanhas, worklist de revogação")
        Component(report, "report (report.py)", "Python", "Agrega em JSON e Markdown")
    }

    Rel(spa, routes, "chama", "JSON/HTTP")
    Rel(routes, store, "lê e edita")
    Rel(routes, report, "agrega")
    Rel(routes, sod, "consulta")
    Rel(routes, reach, "consulta")
    Rel(routes, jml, "consulta")
    Rel(routes, recert, "consulta")
    Rel(store, dbc, "persiste snapshot")
    Rel(store, loader, "seed padrão")
    Rel(store, model, "valida")
    Rel(dbc, db, "SQL")
    Rel(loader, model, "constroi")
    Rel(access, model, "lê")
    Rel(sod, access, "usa")
    Rel(recert, sod, "usa")
    Rel(recert, jml, "usa")
    Rel(recert, reach, "usa")
    Rel(report, sod, "usa")
    Rel(report, reach, "usa")
    Rel(report, jml, "usa")
    Rel(report, recert, "usa")

    UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")
```

Se preferir uma visão só de dependências entre módulos (renderiza em qualquer lugar):

```mermaid
flowchart TD
    routes[api.py] --> store[store.py]
    routes --> report[report.py]
    store --> dbc[db.py]
    store --> loader[loader.py]
    store --> model[model.py]
    dbc --> model
    loader --> model
    report --> sod[sod.py]
    report --> reach[reachability.py]
    report --> jml[jml.py]
    report --> recert[recert.py]
    sod --> access[access.py]
    recert --> sod
    recert --> jml
    recert --> reach
    access --> model
    reach --> model
    jml --> access
```

## Sequência: traçar um caminho de escalonamento

O fluxo da joia do projeto. O usuário escolhe um target sensível e uma identity, e o dashboard
desenha a rota no grafo.

```mermaid
sequenceDiagram
    autonumber
    actor U as Usuário
    participant SPA as Dashboard
    participant API as API (routes)
    participant R as reachability
    participant M as Dataset (memória)

    U->>SPA: escolhe target + identity, clica "Trace path"
    SPA->>API: GET /api/graph/path?identity&target
    API->>R: reach_path(ds, identity, target)
    R->>M: build_graph(ds)
    R->>R: shortest_path e classifica (assume? cross-account?)
    R-->>API: ReachPath (steps, uses_assume, crosses_account)
    API->>R: export_cytoscape(ds, highlight_path)
    R-->>API: grafo com a rota destacada
    API-->>SPA: { reachable, path, graph }
    SPA-->>U: grafo destacado + passo a passo da rota
```

## Sequência: editar dado e recalcular

Toda edição revalida o `Dataset` inteiro antes de gravar. Só um snapshot válido chega ao banco.

```mermaid
sequenceDiagram
    autonumber
    actor U as Usuário
    participant SPA as Dashboard (editor)
    participant API as API (routes)
    participant S as DataStore
    participant DS as Dataset (Pydantic)
    participant DB as Banco

    U->>SPA: cria/edita um item e salva
    SPA->>API: POST /api/data/{kind}
    API->>S: upsert(kind, obj)
    S->>DS: model_validate(payload candidato)
    alt integridade quebrada
        DS-->>S: ValidationError
        S-->>API: StoreError
        API-->>SPA: 400 com a mensagem do erro
        SPA-->>U: mostra a rejeição (nada muda)
    else válido
        DS-->>S: Dataset novo
        S->>DB: seed(snapshot validado) em transação
        S-->>API: ok
        API->>API: headline_metrics(dataset)
        API-->>SPA: 200 + métricas recalculadas
        SPA-->>U: findings atualizados
    end
```

## Sequência: restore defaults

O mecanismo que garante que o demo público sempre volta a um estado bom.

```mermaid
sequenceDiagram
    autonumber
    actor U as Usuário
    participant SPA as Dashboard
    participant API as API (routes)
    participant S as DataStore
    participant DB as Banco

    U->>SPA: clica "Restore defaults"
    SPA->>API: POST /api/data/restore
    API->>S: restore_defaults()
    S->>DB: seed(payload padrão embutido)
    S->>S: recarrega Dataset em memória
    S-->>API: ok
    API-->>SPA: 200 + métricas do padrão
    SPA-->>U: dataset de volta ao seed
```

## Sequência: boot e seed automático

Na primeira subida (banco vazio) o app se semeia sozinho a partir do YAML.

```mermaid
sequenceDiagram
    autonumber
    participant Up as Uvicorn
    participant API as API (lifespan)
    participant S as DataStore
    participant DB as Banco
    participant Y as Seed YAML

    Up->>API: startup (lifespan)
    API->>S: inicializa DataStore
    S->>DB: cria tabelas se não existem
    S->>DB: banco está vazio?
    alt vazio
        S->>Y: carrega dataset padrão
        S->>DB: seed(padrão)
    end
    S->>DB: to_payload()
    S->>S: valida e mantém Dataset em memória
    opt DEMO_RESET_MINUTES > 0
        API->>API: agenda restore periódico
    end
```
