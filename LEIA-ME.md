# LEIA-ME — Instalação e condução (Aula 2)

> ⚠️ App **deliberadamente vulnerável**. Só em rede isolada de laboratório, em
> máquina descartável. Nunca na internet nem com dados reais.

## 1. Instalar (XAMPP / Windows)
1. Copie a pasta `aula02/` para `C:\xampp\htdocs\aula02\`.
2. Inicie **Apache** e **MySQL** no painel do XAMPP.
3. Abra `http://localhost/aula02/install.php` — cria o banco `portal_ifac_aula2`,
   as tabelas, os usuários/boletins de exemplo e os arquivos-alvo das missões de
   XXE e Command Injection (`storage/flag_xxe.txt`, `storage/flag_cmd.txt`).
4. Clique em **“Ir para o portal”**.

Em Linux (Apache + PHP + MariaDB), copie para o `DocumentRoot` equivalente e
ajuste as credenciais do banco em `config.php` se não for root/sem senha
(ou exporte `IFAC_DB_USER` / `IFAC_DB_PASS` / `IFAC_DB_NAME`).

## 2. Acesso pelos alunos (rede local)
- Descubra o IP do professor (`ipconfig` no Windows / `ip a` no Linux).
- Os alunos acessam `http://<IP-do-professor>/aula02/`.
- Libere a porta 80 no firewall do Windows para a rede local, se necessário.

## 3. Contas
| Usuário | Senha | Papel |
|--------|-------|-------|
| `aluno1` | `123` | aluno |
| `aluno2` | `bruno` | aluno |
| `aluno3` | `senha` | aluno |
| `prof1` | `123` | professor |
| `admin` | `admin` | admin |

Console legado (missão de credencial de fábrica): `admin` / `admin123`.

## 4. Toggle MODO VULNERÁVEL / MODO SEGURO
- Botão no topo do site: grava um override **só no seu navegador** (bom para
  demonstrar o ataque e, logo depois, a correção lado a lado).
- Global: edite `SECURE_DEFAULT` em `config.php` (vale para todos os acessos).
- Observação: o `MODO SEGURO` também **desliga o modo debug** (`DEBUG`) e passa a
  enviar os cabeçalhos de segurança.

## 5. Placar (CTF)
Cada missão revela uma `FLAG{...}`. Os alunos enviam em `placar.php` (nome da
equipe + flag) e o ranking soma os pontos. São 11 flags, 1340 pontos no total.

## 6. Limpeza pós-aula
1. Pare Apache e MySQL no XAMPP.
2. Apague o banco: no phpMyAdmin, remova `portal_ifac_aula2` (ou
   `DROP DATABASE portal_ifac_aula2;`).
3. Apague a pasta `aula02/` do `htdocs`.
4. Reabrir `install.php` recria tudo do zero (inclusive o placar), caso queira
   repetir a aula com outra turma.
