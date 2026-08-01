# Conceitos: IAM, IGA, RBAC e ABAC

Este documento explica, em nível de especialista, os quatro conceitos que dão nome e sentido ao
projeto: o que cada um é, por que está aqui, e qual a intenção de modelá-lo num laboratório.
Termos técnicos ficam em inglês de propósito, porque é o vocabulário que a área usa.

Se você quer só rodar, comece pelo [README](../README.md). Se quer o modelo de dados, veja
[modelo-de-dominio.md](modelo-de-dominio.md). Aqui o foco é o porquê.

## O quadro geral

Controle de acesso responde duas perguntas diferentes, que costumam ser confundidas:

- **Quem é você?** Isso é autenticação (login, MFA, sessão). O projeto não trata disso.
- **O que você pode fazer, e você deveria poder?** Isso é autorização e, acima dela,
  governança. É aqui que o projeto vive.

IAM cuida de conceder e aplicar acesso. IGA cuida de garantir que o acesso concedido continua
certo ao longo do tempo. RBAC e ABAC são dois modelos de como o acesso é concedido. O lab
implementa o raciocínio de IGA sobre um acesso concedido por RBAC e por ABAC.

## IAM (Identity and Access Management)

**O que é.** A disciplina e o conjunto de sistemas que administram identidades (pessoas e
service accounts) e o acesso delas a recursos: criar e desativar contas, autenticar, e aplicar
policies de autorização em runtime. Na AWS, é o serviço IAM com users, roles, groups e policies;
num IdP corporativo, é o diretório mais o SSO.

**O foco do IAM é operacional e em tempo real:** dado um pedido, permitir ou negar agora.

**Por que aparece no projeto.** O lab modela os objetos de IAM (Account, Entitlement, Group,
Role, Identity) porque são o substrato sobre o qual a governança raciocina. Mas o projeto é
deliberadamente **read-only** sobre esse substrato: ele não autentica ninguém nem concede
acesso, ele analisa o acesso que já existe. Num deployment real, o loader leria um export
read-only de uma conta AWS ou de um IdP; os engines não mudariam.

## IGA (Identity Governance and Administration)

**O que é.** A camada acima do IAM que responde "o acesso que existe está correto?". IGA cobre
revisão de acesso (access review e recertification), detecção de Segregation of Duties, análise
de risco de acesso, e o ciclo de vida joiner/mover/leaver. Onde o IAM pergunta "posso permitir
este pedido?", o IGA pergunta "por que esta pessoa ainda tem isto, e quem revisou?".

**Por que existe.** Acesso apodrece. As pessoas mudam de função e acumulam permissões (privilege
creep), gente sai e o acesso fica (orphaned access), e combinações perigosas se formam sem
ninguém decidir por elas (por exemplo, criar um fornecedor e aprovar o pagamento a ele). IAM
concede; IGA é o controle que impede a concessão de virar risco silencioso.

**Por que é o coração do projeto.** As quatro análises do lab são as quatro perguntas canônicas
de IGA, cada uma com procedência e um resultado acionável:

| Pergunta de IGA | Engine no projeto |
| --- | --- |
| Quem carrega uma combinação tóxica de deveres? | Segregation of Duties (`sod.py`) |
| Quem consegue alcançar um privilégio sensível, e por qual caminho? | Privilege reachability (`reachability.py`) |
| Qual acesso é resíduo de mudança de função, de leaver, ou está dormante? | Lifecycle JML (`jml.py`) |
| Diante disso, o que revogar primeiro, com um score explicável? | Recertification (`recert.py`) |

A intenção expert é mostrar o **raciocínio inteiro**, não só um alerta: cada finding diz de onde
o acesso veio (procedência) e onde se conserta, porque um achado sem procedência é barulho, não
governança.

## RBAC (Role-Based Access Control)

**O que é.** Acesso concedido por **papel/grupo**: a pessoa entra num grupo e herda as
permissões daquele grupo, inclusive por nesting (um grupo que participa de outro). É o modelo
mais comum e o mais fácil de auditar, porque o vínculo é explícito e durável.

**Como o projeto modela.** `Group` carrega entitlements e pode aninhar em outro via `member_of`;
o `access.py` resolve o fecho transitivo dos grupos e guarda a cadeia exata que trouxe cada
entitlement (`grp-finance-lead -> grp-payments-ops`). No grafo, o RBAC aparece como o caminho
identity -> group -> entitlement, pintado em teal.

**Força e fraqueza.** Força: explícito, revisável, some quando a pessoa sai do grupo. Fraqueza:
explosão de grupos e nesting profundo escondem combinações tóxicas herdadas. O caso semeado no
dataset é exatamente esse: um grupo de finance lead que aninha ops e approvers, então todo lead
herda uma violação de SoD sem um único grant direto.

## ABAC (Attribute-Based Access Control)

**O que é.** Acesso concedido por **atributo**: uma regra concede permissão a qualquer identity
cujos atributos casem uma condição (por exemplo, `department == Security`). Ninguém atribui a
regra a uma pessoa; ela vale sozinha para quem tiver o atributo, e deixa de valer quando o
atributo muda. É o modelo por trás de tag-based access control e das condition policies da AWS.

**Como o projeto modela.** `AbacRule` casa atributos escalares da identity (department, title,
type, status, home_account_id) e concede entitlements; o `access.py` resolve isso como standing
access com procedência `abac via <regra>`. No grafo, o ABAC aparece como a aresta direta
identity -> entitlement, pintada em azul, distinta do teal do RBAC.

**Força e fraqueza.** Força: escala sem criar grupo para tudo, e o acesso acompanha o cadastro
da pessoa. Fraqueza, e o motivo de estar aqui: é o acesso **implícito**, que aparece e some sem
um clique de provisioning, e por isso o mais fácil de esquecer numa revisão. Uma ferramenta de
governança que só olha grupos (RBAC) é cega para metade do acesso real.

## RBAC e ABAC juntos, e por que os dois

Organizações reais usam os dois ao mesmo tempo: RBAC para as funções estáveis, ABAC para o que
depende de atributo (departamento, tipo de conta, localização). O diferencial do lab é tratar os
dois como **standing access de primeira classe**: ambos somam no acesso efetivo e alimentam SoD,
creep e recertification do mesmo jeito. A única diferença que sobra é a **procedência**, e é ela
que torna o finding acionável (consertar no grant direto, no grupo, ou na regra de atributo). O
dashboard separa os dois por cor no grafo justamente para o mecanismo ficar visível.

O escopo honesto está em [limitacoes.md](limitacoes.md): o ABAC aqui é matching de atributo por
igualdade, não a linguagem completa de policy condition (sem operadores de comparação, sem tag
de recurso, sem variável de sessão). É suficiente para demonstrar o mecanismo e o risco, não
para substituir um policy evaluator.

## A intenção do projeto

Portar isto para uma fonte real (um export de conta AWS, um dump de IdP) é trocar o loader, não
os engines. O lab existe para demonstrar, de forma fiel e testável, o raciocínio de IAM e IGA:
resolver acesso efetivo com procedência, detectar toxic combinations, computar escalonamento
cross-account e transformar tudo numa revisão defensável, pior primeiro, com o escopo do que ele
não faz escrito antes de qualquer conclusão.
