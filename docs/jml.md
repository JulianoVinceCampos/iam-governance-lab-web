# Joiner / Mover / Leaver

A análise de lifecycle compara o que uma identity *deveria* ter, dada a baseline do seu título,
com o que ela *tem*. As baselines e o threshold de dormancy ficam no `policy.yaml`.

## Joiner gaps

Para cada identity ativa cujo título tem baseline, compara o conjunto de grupos esperado com o
conjunto que ela tem:

- grupos **faltando**: a identity está under-provisioned para a função.
- grupos **a mais**: acesso além da baseline, em geral arrastado de uma função anterior. É o
  sinal de mover.

## Privilege creep

Entitlements de standing access além do que a baseline do título concede. Onde joiner gaps
trabalham no nível de grupo, creep trabalha no nível de entitlement e segue o nesting, então
pega acesso que vazou por um grupo que a baseline nunca pretendeu. Cada item de creep guarda sua
procedência, então dá para ver se entrou direto, por um grupo (RBAC) ou por atributo (ABAC).

O caso canônico do dataset: um engineer promovido para um grupo de admin mas cujo título nunca
foi atualizado. A baseline de "Dev Engineer" é o grupo de engineers; o grupo de admin aninha ele
e adiciona um entitlement de admin, que aparece como creep.

## Orphaned access (leavers)

Identities disabled ou terminated que ainda carregam standing access. São as falhas de leaver e
em geral a limpeza de maior valor, porque a conta nem deveria ser usável. A recertification
sempre recomenda revogar o acesso de um leaver, independente do score.

## Dormancy

Identities ativas que carregam acesso mas não têm atividade dentro de `dormancy_days`. Dormancy é
um sinal suave, não uma falha: eleva o score de recert e marca o acesso para revisão em vez de
forçar revogação. Uma identity sem acesso não é reportada como dormante, porque não há o que
revisar.
