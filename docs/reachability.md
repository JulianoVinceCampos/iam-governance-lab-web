# Privilege reachability

A análise central. Ela responde "quem consegue alcançar o quê, atravessando N contas, e por qual
caminho" transformando acesso num grafo dirigido e computando reachability sobre ele.

## O grafo

Uma aresta `u -> v` lê-se como "ter u permite obter v":

| Aresta | Significado |
| --- | --- |
| identity -> entitlement | grant direto |
| identity -> group | membership |
| group -> group | membership aninhada (filho -> pai) |
| group -> entitlement | o grupo carrega o entitlement |
| entitlement -> role | o entitlement permite assumir o role (`sts:AssumeRole`) |
| role -> entitlement | o role carrega o entitlement depois de assumido |

Os nós são tipados (`identity`, `group`, `role`, `entitlement`) e carregam sua conta e, no caso
de entitlement, o privilege level. O grafo é montado com NetworkX.

## Trust: os dois lados precisam concordar

A aresta de `assume` é a única com pré-condição. Ela só existe quando:

1. o lado **identity-based** concorda: um entitlement lista o role em `assume_targets`, e
2. o lado **resource-based** concorda: o `trusts` do role admite a conta de origem, ou confia
   em `*`.

Isso espelha a AWS na granularidade de conta, onde tanto uma identity policy permitindo
`sts:AssumeRole` quanto uma role trust policy aceitando o principal são necessárias. Modelar só
um lado inventaria caminhos de escalonamento que não existem, ou perderia caminhos que existem.

Um trust `*` é alcançável por qualquer conta. Ele é marcado à parte, porque um wildcard trust
transforma qualquer capacidade de assume em qualquer lugar num caminho até aquele role.

## Standing versus escalonamento

Para um entitlement alcançável, o engine verifica se existe caminho sem atravessar nenhuma
aresta de `assume`:

- alcançável sem assumir -> **standing** access;
- alcançável só assumindo um ou mais roles -> **escalonamento**.

Escalonamento que ainda atravessa fronteira de conta é o caso relevante para segurança. Uma
identity numa conta de development que consegue assumir role até um entitlement admin em produção
é exatamente o finding que uma auditoria deveria destacar, e que relatório de standing access
nunca destaca.

## Caminhos

Para um target, o `who_can_reach` devolve toda identity com caminho até ele, cada uma com o
caminho mais curto, se usa assunção e se atravessa contas. A API expõe uma consulta de caminho
único (`/api/graph/path`) que o dashboard usa para destacar uma rota de escalonamento no grafo e
imprimi-la passo a passo.

O caminho mais curto é escolha deliberada: mostra o jeito *mais fácil* de alcançar um target, que
é o primeiro que um reviewer deveria raciocinar. Enumerar todos os caminhos é exponencial e
raramente muda a decisão.

## Targets sensíveis

A auditoria foca em entitlements de privilege level `high` ou `critical`. São esses os targets
para os quais vale perguntar "quem chega aqui". Entitlements de privilégio menor continuam no
grafo como hops intermediários.

## Casos de borda tratados

- **Ciclos de nesting de grupo**: impossíveis, rejeitados no load.
- **Roles mortos**: um role que ninguém consegue assumir (nenhum entitlement o alveja, ou o trust
  nunca admite) simplesmente não tem aresta de assume de entrada e é inalcançável. Isso é
  correto, e o dataset inclui um de propósito.
- **Identities terminadas**: permanecem no grafo. Um engineer terminado que ainda alcança admin
  em produção é ao mesmo tempo um finding de orphaned access e de escalonamento, e ambos são
  reportados.
