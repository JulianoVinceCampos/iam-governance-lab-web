# Recertification e risk score

Recertification transforma "aqui está todo o acesso" em "aqui está o acesso que um manager
precisa revisar, pior primeiro, com uma recomendação". O score é determinístico e cada termo é
documentado, porque um número de risco que ninguém sabe explicar é pior que nenhum número.

## A fórmula

Para uma linha `(identity, entitlement)`, o score é limitado a 0..100:

| Termo | Valor | Quando |
| --- | --- | --- |
| base | peso do privilege | low 5, medium 15, high 30, critical 45 |
| SoD | +30 | o par participa de uma violação de SoD |
| dormancy | +20 | a identity está dormante (`policy.dormancy_days`) |
| escalonamento | +15 | o entitlement habilita assunção de role |

Exemplo: um entitlement critical que está numa violação de SoD, carregado por uma identity
dormante, e que habilita assunção, pontua `45 + 30 + 20 + 15 = 110`, limitado a 100. Um
entitlement medium numa SoD pontua `15 + 30 = 45`.

## Buckets e recomendação

| Score | Bucket | Recomendação |
| --- | --- | --- |
| < 25 | low | keep |
| 25..49 | medium | review |
| 50..74 | high | revoke |
| >= 75 | critical | revoke |

Uma exceção: identity disabled ou terminated que ainda carrega o entitlement é sempre **revoke**,
qualquer que seja o score. Standing access de leaver é limpeza, não julgamento.

## Por que esses pesos

Os pesos codificam uma opinião defensável, não uma lei da natureza, e ficam num só lugar para
poderem ser discutidos e mudados:

- Privilege é a base porque um grant de baixo privilégio, mesmo arriscado, é problema menor que
  um sobre-privilegiado.
- SoD é o maior termo aditivo porque falha de separação é quebra ativa de control, não só
  exposição.
- Dormancy e escalonamento são multiplicadores de exposição: acesso sem uso e acesso assumível
  ambos ampliam o raio de dano sem serem, por si, uma quebra.

## Campanhas e worklist

- **Campanhas** agrupam o acesso de cada identity sob seu manager (o reviewer), com os reviewees
  ordenados pior primeiro. Identities sem manager caem sob um reviewer "unassigned", que é, ele
  mesmo, um finding.
- **A worklist** é a lista plana de toda linha recomendada para revogação, pior score primeiro,
  pronta para entregar a quem executa a mudança.

A ferramenta para na recomendação. Ela emite uma worklist; nunca revoga nada, porque é read-only
sobre a fonte por design.
