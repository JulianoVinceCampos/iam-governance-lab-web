# Política de segurança

## Escopo

Este é um lab de portfólio sobre dados sintéticos. Ele não guarda dado real, não integra com
nenhuma fonte de identidade de produção e, no modo demo, roda com acesso de escrita aberto de
propósito para qualquer visitante editar o cenário. Trate a instância pública como descartável.

## Camadas de defesa no repositório

| Camada | Ferramenta | O que cobre |
| --- | --- | --- |
| Lint | ruff | Estilo e armadilhas comuns |
| Tipos | mypy (strict) | Contratos de tipo em todo o código |
| Testes | pytest (3.11 a 3.13) | Correção dos engines e da API |
| SAST | Semgrep + CodeQL | Análise estática do código-fonte |
| Dependências | pip-audit + Dependabot | CVE conhecido em lib, com PR de bump automático |
| Runtime | Basic auth opcional na escrita | Protege o editor quando `IAMGOV_AUTH_USER/PASS` estão setados |

## Reportar uma vulnerabilidade

Use o "Report a vulnerability" da aba Security do GitHub (private vulnerability reporting).
Descreva o passo a passo de reprodução e o impacto. Como o lab é sintético e read-only sobre a
fonte, o interesse maior é em falha na própria aplicação (a API, o editor, o container), não
nos dados de exemplo.

## Boas práticas ao hospedar

- Ponha TLS na frente. O Basic auth de escrita é encodado, não encriptado.
- Em demo público, deixe o `DEMO_RESET_MINUTES` ligado, para o cenário se autocurar.
- Para persistir edições, monte um disco em `/data`; caso contrário o estado é efêmero e
  volta ao seed a cada start, que é o comportamento desejado num demo aberto.
