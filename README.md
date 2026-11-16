# Portal Acadêmico IFAC — Aula 2 (A05 Injection + A02 Security Misconfiguration)

Aplicação **deliberadamente vulnerável** (PHP + MySQL/MariaDB) para a segunda
aula prática da trilha **OWASP Top 10 2025**. Mesma mecânica do lab de A01: os
alunos encontram, exploram e corrigem **11 vulnerabilidades** no estilo CTF —
cada falha revela uma flag `FLAG{...}` que vale pontos no placar.

Categorias cobertas:

- **A05:2025 — Injection** (SQLi, XSS, Command Injection, XXE)
- **A02:2025 — Security Misconfiguration** (credencial de fábrica, erro verboso,
  modo debug, CORS, cabeçalhos de segurança)

> ⚠️ **AVISO DE SEGURANÇA.** Este software tem falhas de propósito. Rode **apenas**
> em rede isolada de laboratório, em máquina descartável. **Nunca** exponha à
> internet nem instale em máquina com dados reais. As missões de XXE e Command
> Injection alcançam o sistema de arquivos do servidor.

## Começo rápido (XAMPP / Windows)

1. Copie a pasta para `C:\xampp\htdocs\aula02\`.
2. No XAMPP, inicie **Apache** e **MySQL**.
3. Abra `http://localhost/aula02/install.php` (cria banco, tabelas e dados).
4. Acesse `http://localhost/aula02/` — ou `http://<IP-do-professor>/aula02/`
   pelos alunos na rede local.

Passo a passo completo (firewall, IP, limpeza): **[LEIA-ME.md](LEIA-ME.md)**.

## Documentação

- **[LEIA-ME.md](LEIA-ME.md)** — instalação, acesso em rede, contas, o toggle
  MODO VULNERÁVEL/MODO SEGURO e limpeza pós-aula.
- **[ROTEIRO-PROFESSOR.md](ROTEIRO-PROFESSOR.md)** — guia por missão (onde achar,
  como explorar, impacto, CWEs, flag e correção). **Contém o gabarito.**
- **[GABARITO-impressao.html](GABARITO-impressao.html)** — tabela das 11 flags
  para imprimir. **Material do professor.**
- **[FOLHA-ALUNOS.html](FOLHA-ALUNOS.html)** — folha de missões para distribuir
  (sem as flags). Imprima pelo navegador.

## Contas de demonstração

| Usuário | Senha | Papel |
|--------|-------|-------|
| `aluno1` | `123` | aluno |
| `aluno2` | `bruno` | aluno |
| `aluno3` | `senha` | aluno |
| `prof1` | `123` | professor |
| `admin` | `admin` | admin |

Console legado (missão A02): `admin` / `admin123`.

## As 11 missões (CWEs)

**A05 Injection** — SQLi bypass de login (CWE-89/564) · SQLi UNION (CWE-89/200) ·
XSS refletido (CWE-79/80) · XSS armazenado (CWE-79/116) · Command Injection
(CWE-78/77) · XXE (CWE-611/827/776).

**A02 Security Misconfiguration** — credencial de fábrica (CWE-798/1392/1188) ·
erro verboso / stack trace (CWE-209/497/756) · modo debug exposto
(CWE-489/16/215) · CORS liberado (CWE-942/346) · cabeçalhos de segurança
ausentes / clickjacking (CWE-1021/693/16).

## O toggle MODO VULNERÁVEL / MODO SEGURO

Toda falha tem dois caminhos no código (`if (SECURE) { ...correção... } else
{ ...vulnerável... }`). Alterne pelo botão no topo do site (vale só para o seu
navegador — ótimo para demonstrar lado a lado) ou pela constante `SECURE_DEFAULT`
em `config.php` (vale para todos).
