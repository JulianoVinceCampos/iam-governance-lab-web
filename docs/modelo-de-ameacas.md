# Modelo de ameaças

O que a ferramenta pretende pegar, o que ela assume, e onde ela para.

## O que detecta

- **Quebras de segregation of duties**: uma identity que carrega efetivamente duas capacidades
  conflitantes, por grant direto, herdado via nesting de grupo (RBAC) ou concedido por atributo
  (ABAC).
- **Caminhos de privilege escalation**: uma identity que consegue assumir role até um entitlement
  sensível que não tem direto, com o escalonamento cross-account destacado à parte.
- **Exposição por wildcard trust**: roles que confiam em `*` e portanto são alcançáveis por
  qualquer conta com capacidade de assume.
- **Resíduo de leaver**: identities disabled ou terminated que ainda carregam standing access.
- **Acúmulo de privilégio**: acesso além da baseline de uma função (creep) e acesso sem uso
  recente (dormancy).

## Premissas

- O dado de entrada é um **snapshot fiel** de grants, memberships e trust. A ferramenta raciocina
  sobre o que o dado diz; não descobre acesso que o dado omite.
- Nesting de grupo e trust são como declarados. Não há herança escondida ou shadow admin fora do
  modelo.
- O **reviewer é confiável**. A ferramenta produz uma worklist; um humano ou um processo
  automatizado à parte age sobre ela. A ferramenta em si é read-only e não tem caminho de escrita
  para a fonte.

## Fora de escopo

- **Detecção de abuso em runtime.** Isto é análise estática de entitlements, não um SIEM. Não
  detecta um escalonamento sendo exercido, roubo de credencial ou comportamento anômalo.
- **Fidelidade de avaliação de policy.** Condition keys, permission boundaries, SCPs e
  explicit-deny não são modelados (ver [limitacoes.md](limitacoes.md)). Um caminho que a
  ferramenta reporta poderia estar bloqueado em runtime por uma condition que o modelo não vê, e
  vice-versa.
- **Confiança na fonte de dados.** Se o export que alimenta a ferramenta está velho ou adulterado,
  os findings herdam isso. A integridade do pipeline que produz `data/` é assumida, não verificada
  aqui.

## Por que read-only importa

Uma ferramenta de governança com acesso de escrita ao store de identidades é ela mesma um alvo de
alto valor e um novo problema de SoD: quem controla a ferramenta de remediação controla o acesso.
A análise aqui não tem caminho de escrita para nenhuma fonte real; ela emite uma worklist para um
ator à parte executar, mantendo separadas a capacidade de análise e a de mudança, que é o mesmo
princípio que a ferramenta audita. O editor de dados do dashboard escreve só no input sintético
do lab, e num deployment real estaria desabilitado ou apontado para uma cópia de staging, nunca
para a fonte de verdade que a análise lê.
