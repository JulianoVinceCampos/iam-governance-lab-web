# Modelo de domínio

O modelo é de propósito próximo de como uma ferramenta de IGA raciocina sobre acesso, não de
como um IdP específico guarda os dados. São cinco entidades, e é na relação entre elas que os
findings nascem.

## Entidades

| Entidade | O que é |
| --- | --- |
| **Account** | Uma fronteira de isolamento: uma conta AWS, um tenant, uma org unit. O trust cross-account entre elas é onde mora o escalonamento. |
| **Entitlement** | Um grant atômico: um conjunto de actions sobre um resource, num privilege level. Pode listar `assume_targets` (roles que ele permite assumir). |
| **Group** | Um agrupamento RBAC que carrega entitlements e pode aninhar em outro via `member_of`. Membros herdam os entitlements do pai. |
| **Role** | Um principal *assumível* (estilo STS). Carrega entitlements depois de assumido, e tem uma trust policy: quais contas de origem podem assumi-lo. |
| **Identity** | Um principal humano ou service. Tem entitlements diretos e memberships de grupo, um status, um manager, um título e um sinal de última atividade. |

## Standing access versus reachable access

Essa distinção atravessa o projeto inteiro.

- **Standing access** é o que a identity carrega sem assumir nada: seus entitlements diretos,
  mais o fecho transitivo dos entitlements dos grupos (RBAC), mais os concedidos por regra de
  atributo (ABAC). SoD e recertification operam sobre standing access, porque é o que a
  identity de fato *tem*.
- **Reachable access** soma a assunção de role. Seguindo as arestas de assume até o fixpoint,
  chega-se a tudo que a identity conseguiria obter escalando. A análise de reachability opera
  sobre esse conjunto maior.

Ninguém "tem" um role até assumi-lo, então role nunca é standing access. Manter os dois
separados é o que permite dizer "a Erin tem read-only em dev, mas consegue assumir role até
admin em produção", que é o finding que importa.

## Dois mecanismos de autorização: RBAC e ABAC

Uma organização real concede acesso por dois caminhos, e o lab modela os dois:

- **RBAC** (role-based) é o acesso por **grupo**: a identity participa de um grupo, direta ou
  por nesting, e herda os entitlements dele. O vínculo é explícito e durável, e some quando a
  pessoa sai do grupo. É a espinha do modelo (`Group`, `member_of`).
- **ABAC** (attribute-based) é o acesso por **atributo**: uma `AbacRule` concede entitlements a
  qualquer identity cujos atributos casem uma condição (por exemplo, `department == Security`).
  Ninguém atribui a regra a ninguém; ela vale sozinha para quem tiver o atributo, e deixa de
  valer quando o atributo muda. É o standing access que aparece sem um clique de provisioning,
  e por isso mesmo é o mais fácil de esquecer numa revisão.

As condições de ABAC só casam atributos estáveis e de baixo risco de digitação (department,
title, type, status, home_account_id), com semântica E entre elas. Os dois mecanismos somam no
standing access e alimentam SoD, creep e recertification do mesmo jeito; o que muda é a
procedência, e o dashboard os separa por cor no grafo (grupo em teal, atributo em azul).

## Procedência

A resolução de acesso efetivo guarda, para cada entitlement, o *porquê* de a identity tê-lo: um
grant direto, a cadeia exata de grupos aninhados que o trouxe (RBAC), ou a regra de atributo
que o concedeu (ABAC). Procedência é o que torna o finding acionável. Grant direto se revoga na
identity; herdado se conserta no grupo, e consertar lá conserta para todo mundo daquele grupo;
por atributo se conserta na regra de ABAC ou no atributo da identity. Quando um mesmo
entitlement vem por mais de um caminho, a procedência mostrada é a mais próxima da identity
(direto vence atributo, que vence grupo).

## Integridade

O dataset é validado antes de qualquer cálculo. O loader rejeita:

- referência inexistente (entitlement apontando para account que não existe, membership em grupo
  inexistente, `assume_target` que não é role, `AbacRule` concedendo entitlement inexistente),
- id duplicado dentro de qualquer coleção,
- ciclo no nesting de grupo.

Dataset quebrado falha alto no momento do load. Nunca produz finding calado e errado.

## Tunables de governança

O `policy.yaml` guarda os botões, para que uma execução seja reproduzível e as definições sejam
auditáveis em vez de hardcoded: o threshold de dormancy, e as **baselines** de joiner (o
conjunto exato de grupos que um título deveria ter). Baselines alimentam tanto a detecção de
under-provisioning quanto o privilege creep.
