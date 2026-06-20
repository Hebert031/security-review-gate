# Exemplos de Testes — Security Review Gate

Todos os comandos devem ser executados a partir da raiz do projeto:

```bash
cd /home/hebert/estudos/security-review-gate
```

---

## 1. Testes unitários automatizados

Roda todos os testes do diretório `tests/`:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Resultado esperado: todos os testes passando (`OK`).

---

## 2. Diffs de exemplo — execução manual

### 2.1 `exemplo.diff` — HIGH (score alto)

Contém: `verify=False` + hardcoded `API_KEY` + SQL por concatenação de string.

```bash
PYTHONPATH=src python3 -m security_review_gate.cli --file exemplo.diff
```

**Sinais esperados:** controle de segurança desabilitado, possível material secreto, SQL alterado.  
**Level esperado:** `high`

---

### 2.2 `examples/risky.diff` — HIGH

Contém: `verify=False` + leitura de token do header + senha hardcoded.

```bash
PYTHONPATH=src python3 -m security_review_gate.cli --file examples/risky.diff
```

**Sinais esperados:** controle de segurança desabilitado, autenticação alterada.  
**Level esperado:** `high`

---

### 2.3 `examples/low_docs_only.diff` — LOW (score zero)

Apenas alterações em `.md` — nenhum sinal de segurança.

```bash
PYTHONPATH=src python3 -m security_review_gate.cli --file examples/low_docs_only.diff
```

**Sinais esperados:** nenhum.  
**Level esperado:** `low`, score `0`

---

### 2.4 `examples/medium_sql_input.diff` — MEDIUM

Contém: SQL com concatenação de entrada do usuário + `request.args` + `request.json`.  
Tem arquivo de teste alterado (desconto de 5 pontos no score).

```bash
PYTHONPATH=src python3 -m security_review_gate.cli --file examples/medium_sql_input.diff
```

**Sinais esperados:** SQL alterado, tratamento de entrada não confiável.  
**Level esperado:** `medium`

---

### 2.5 `examples/high_secret_disable.diff` — HIGH (score máximo esperado)

Contém: dois segredos hardcoded (`API_KEY`, `CLIENT_SECRET`) + `verify=False` + `CORS(app)` aberto.

```bash
PYTHONPATH=src python3 -m security_review_gate.cli --file examples/high_secret_disable.diff
```

**Sinais esperados:** material secreto, controle de segurança desabilitado, arquivo sensível alterado.  
**Level esperado:** `high`

---

### 2.6 `examples/high_infra_deps.diff` — HIGH

Contém: workflow de CI/CD com `curl | bash` + dependências novas + pod Kubernetes com `privileged: true`.

```bash
PYTHONPATH=src python3 -m security_review_gate.cli --file examples/high_infra_deps.diff
```

**Sinais esperados:** infraestrutura alterada, dependências alteradas.  
**Level esperado:** `high`

---

### 2.7 `examples/high_command_exec.diff` — HIGH

Contém: `os.system` com input do usuário + `eval()` + endpoint `/run` que executa `exec(code)`.

```bash
PYTHONPATH=src python3 -m security_review_gate.cli --file examples/high_command_exec.diff
```

**Sinais esperados:** execução dinâmica de comandos, tratamento de entrada não confiável.  
**Level esperado:** `high`

---

## 3. Entrada via stdin

Testa o caminho de leitura pelo pipe (sem `--file`):

```bash
cat examples/risky.diff | PYTHONPATH=src python3 -m security_review_gate.cli
```

---

## 4. Limite de tamanho (2 MiB)

Testa que o sistema rejeita diffs maiores que 2 MiB:

```bash
python3 -c "print('x' * (2 * 1024 * 1024 + 1))" | PYTHONPATH=src python3 -m security_review_gate.cli
```

**Resultado esperado:** erro mencionando `2 MiB`.

---

## 5. Resumo dos níveis esperados

| Arquivo                          | Level    | Score aproximado |
|----------------------------------|----------|-----------------|
| `low_docs_only.diff`             | `low`    | 0               |
| `medium_sql_input.diff`          | `medium` | 25–40           |
| `examples/risky.diff`            | `high`   | 55+             |
| `exemplo.diff`                   | `high`   | 70+             |
| `high_secret_disable.diff`       | `high`   | 80+             |
| `high_infra_deps.diff`           | `high`   | 55+             |
| `high_command_exec.diff`         | `high`   | 60+             |
