# Limitações e escopo

Escrito antes dos findings, de propósito. Uma ferramenta de governança que não declara o que
ignora convida a falsa confiança. Isto é um lab sobre um modelo simplificado, não um avaliador de
policy plugado numa nuvem viva.

## O modelo é mais grosso que um IAM real

- **Sem condition keys.** Grants reais da AWS podem ser condicionados a tag, source IP, MFA,
  horário. O modelo trata entitlement como incondicional. Um grant tecnicamente presente mas
  inalcançável na prática (bloqueado por uma condition) ainda é contado aqui.
- **Sem permission boundaries nem SCPs.** Nada limita a permissão efetiva do jeito que uma
  permission boundary ou uma SCP de Organizations limitaria. Acesso efetivo é grants mais herança
  de grupo, ponto.
- **Sem lógica de deny.** Acesso é aditivo. Não há explicit-deny que sobreponha um allow, então o
  modelo não representa "permitido por uma policy, negado por outra".
- **Trust por conta.** O trust de role é modelado como quais *contas* de origem podem assumir, não
  principals específicos, external ids ou session conditions. É uma simplificação fiel do
  `sts:AssumeRole`, não o quadro completo.

## Reachability é estrutural, não runtime

- Reachability responde "existe caminho no grafo de acesso", não "alguém percorreu". Ela não lê
  CloudTrail nem log de atividade para confirmar que um escalonamento foi usado.
- Ela reporta o caminho **mais curto** até cada target, não todos os caminhos. O mais curto é a
  rota mais fácil e a coisa certa para raciocinar primeiro, mas não é enumeração exaustiva.
- Roles mortos (não assumíveis) são corretamente inalcançáveis, mas o modelo não tem noção de um
  role assumível em teoria e inutilizável por um motivo operacional fora dos dados.

## Os dados são sintéticos

O dataset foi inventado para exercitar cada control com clareza. Diretórios reais são mais
bagunçados: milhares de identities, títulos inconsistentes, service accounts sem dono, e
baselines que não existem. O engine foi feito para descer à clareza, não para subir àquela
bagunça.

O editor de dados do dashboard deixa você autorar cenários mutando esse input sintético num
banco, com a mesma validação de integridade que o loader aplica. Isso é autoria de dado de lab,
não escrita numa fonte de identidade de produção. Num deployment real o loader leria um export
read-only e o editor estaria desabilitado ou apontado para uma cópia de staging.

Para um demo público o editor fica aberto de propósito, para os visitantes experimentarem. Isso é
seguro aqui porque o dado é fictício e um "Restore defaults" (e um reset periódico opcional)
reconstrói o dataset inteiro a partir do seed embutido, então um demo apagado ou bagunçado sempre
se recupera. Ligar o par de auth deixa a edição só para o owner e mantém o dashboard visível.

## Para o que isto serve

Uma demonstração fiel e testável do *raciocínio*: como resolver acesso efetivo com procedência,
como detectar toxic combinations, como computar escalonamento cross-account, e como transformar
tudo isso numa revisão defensável, pior primeiro. Portar o loader para uma fonte real (um export
de conta AWS, um dump de IdP) é o próximo passo natural, e os engines não precisariam mudar para
consumi-la.
