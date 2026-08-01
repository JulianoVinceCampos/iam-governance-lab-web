# Segregation of Duties

Uma regra de SoD declara dois baldes de capacidade, `set_a` e `set_b`. Cada balde é uma lista de
selectors. Uma identity viola a regra quando seu **standing access efetivo** casa com pelo menos
um selector de cada balde, espalhado por **pelo menos dois entitlements distintos**.

## Selectors

Um selector casa entitlements de três formas:

- `entitlement`: o id do entitlement está na lista.
- `action`: alguma action do entitlement casa com algum glob da lista (`fnmatch`, então `iam:*`
  casa com `iam:CreateUser`).
- `tag`: o entitlement carrega alguma das tags listadas.

Tag é a opção mais sustentável para regras estilo policy. Marcar os grants com `vendor` e
`payment` deixa a regra de finanças funcionando conforme novos entitlements surgem, sem editar a
regra.

## Por que dois entitlements distintos

Segregation of duties é sobre não acumular duas capacidades conflitantes. Se um único entitlement
casasse com os dois lados de uma regra, isso é regra mal especificada ou um grant único
abrangente demais, não uma falha de separação, então o engine não reporta. Exigir dois
entitlements distintos mantém o sinal limpo.

## Procedência e remediação

Todo match registra como a identity o carrega:

- grant **direto**, consertado revogando na identity;
- **herdado** por RBAC, mostrado como a cadeia de grupos (`grp-finance-lead ->
  grp-payments-ops`), consertado no grupo;
- concedido por **atributo** (ABAC), mostrado como `abac via <regra>`, consertado na regra de
  ABAC ou no atributo da identity.

O `inherited_only` de uma violação é verdadeiro quando nenhum lado veio por grant direto. São
esses os que se conserta uma vez, no grupo (ou na regra de atributo), para todo mundo.

## Exemplo real

No dataset publicado, o `grp-prod-finance-lead` aninha tanto o `grp-prod-payments-ops` (create
vendor) quanto o `grp-prod-payments-approvers` (approve payment). Todo finance lead herda,
portanto, a combinação tóxica inteira sem um único grant direto, e o finding aponta o nesting
como o conserto. Um analista à parte tem vendor por grupo mas payment direto, então essa
violação é de procedência mista e se conserta na identity.

## Negativos honestos

O dataset traz uma regra (`sod-iam-admin-and-payment`) que produz zero violações. Isso é
proposital. Um engine de detecção que só entrega regras que disparam não está sendo testado
contra o caso que mais importa numa auditoria: provar que um control está limpo.
