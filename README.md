# Security Review Gate

MVP para priorizar Pull Requests que merecem revisão de segurança. O sistema
analisa um diff unificado como texto, sem aplicar o patch e sem executar código.

> O resultado indica prioridade de revisão. Ele não confirma nem descarta uma
> vulnerabilidade.

## Modelo de ameaça

### Entrada não confiável

- conteúdo do diff;
- nomes de arquivos;
- mensagens e trechos adicionados;
- arquivos fornecidos pela integração de CI.

### Controles

- o diff nunca é aplicado ou executado;
- a entrada é limitada a 2 MiB;
- o relatório mostra categorias de sinais, não possíveis valores secretos;
- o MVP roda em modo informativo e não bloqueia merge;
- nenhuma informação é enviada a serviços externos.

## Executar

No diretório do projeto:

```bash
PYTHONPATH=src python3 -m security_review_gate.cli --file exemplo.diff
```

Também é possível usar entrada padrão:

```bash
git diff --cached | PYTHONPATH=src python3 -m security_review_gate.cli
```

## Testes

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Estado atual

Esta primeira versão implementa um baseline determinístico. Ele existe para:

1. entregar valor antes de haver dados suficientes;
2. tornar a decisão inicial auditável;
3. estabelecer a referência mínima para um futuro modelo supervisionado.

O treinamento de ML só será adicionado após validar um dataset com rótulos,
licença e divisão por repositório e tempo.

## Limitações

- palavras e caminhos são sinais imperfeitos;
- mudanças pequenas podem ser críticas e receber score baixo;
- alterações legítimas em autenticação podem receber score alto;
- contexto fora do diff não é considerado;
- o baseline não substitui SAST, revisão humana ou testes de segurança.
