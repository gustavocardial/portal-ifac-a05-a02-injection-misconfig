# Roteiro do Professor — Aula 2 (A05 Injection + A02 Security Misconfiguration)

**Contém o gabarito.** Material de uso exclusivo do professor. Para cada missão:
onde achar, como explorar, impacto, CWEs, a flag e como corrigir (o que o
MODO SEGURO faz).

Dica de condução: deixe o site em **MODO VULNERÁVEL** durante a exploração.
Ao revisar cada falha, ligue o **MODO SEGURO** (botão no topo) e mostre o ataque
falhando — o mesmo payload, agora bloqueado.

Pontuação total: **1340 pontos** em 11 missões.

---

## A05 — Injection

### 1) SQL Injection: bypass de login — 120 pts
- **Onde:** `login.php`
- **Explorar:** usuário `admin' --` (senha em branco) ou `' OR '1'='1' LIMIT 1 --`.
  A consulta vira `... WHERE usuario = 'admin' --' AND senha = ''`, o `--`
  comenta a checagem de senha e o login acontece como `admin`.
- **Flag:** `FLAG{sqli_login_bypass_or_1_eq_1}` (aparece no painel após o login).
- **Impacto:** autenticação totalmente contornável; acesso a qualquer conta.
- **CWE:** 89, 564, 943.
- **Correção (MODO SEGURO):** consulta parametrizada (`prepare`/`execute`) e
  `password_verify()` contra o hash — a injeção deixa de ter efeito.

### 2) SQL Injection: UNION extrai dados — 150 pts
- **Onde:** `busca.php` (campo de busca de colegas).
- **Explorar:** a busca devolve 2 colunas. Payload:
  `' UNION SELECT usuario, senha FROM usuarios -- `. Vêm à tona os logins e as
  senhas em texto puro de todos — inclusive a linha de sistema cuja "senha" é a flag.
- **Flag:** `FLAG{sqli_union_vazou_o_hash}` (valor da coluna `senha` da conta `_sistema_`).
- **Impacto:** leitura arbitrária do banco (exfiltração de credenciais/dados).
- **CWE:** 89, 200.
- **Correção:** consulta parametrizada com `LIKE ?` e restrição de colunas/papéis.

### 3) XSS refletido na busca — 100 pts
- **Onde:** `busca.php`
- **Explorar:** `?q=<script>alert(document.domain)</script>` — o termo volta ao
  HTML sem escape e o script executa.
- **Flag:** `FLAG{xss_refletido_na_busca}` (revelada ao refletir um payload).
- **Impacto:** execução de JS no contexto da vítima (roubo de sessão, phishing).
- **CWE:** 79, 80.
- **Correção:** `htmlspecialchars()` em toda saída (o helper `e()`), tanto no
  eco do termo quanto no `value` do input.

### 4) XSS armazenado no mural — 130 pts
- **Onde:** `mural.php`
- **Explorar:** publique um recado com `<img src=x onerror=alert(1)>` ou
  `<script>…</script>`. Fica salvo e dispara para **todos** que abrem o mural.
- **Flag:** `FLAG{xss_armazenado_no_mural}`.
- **Impacto:** XSS persistente — atinge qualquer visitante, inclusive admins.
- **CWE:** 79, 116.
- **Correção:** escapar na exibição (`e()`); idealmente também sanitizar na entrada.

### 5) Command Injection no diagnóstico — 150 pts
- **Onde:** `diagnostico.php` (ferramenta de ping).
- **Explorar:** host `127.0.0.1; cat flag_cmd.txt` — o `;` encerra o ping e o
  segundo comando roda. (O shell é **simulado** para não dar RCE real na máquina
  da aula, mas a brecha — entrada não validada virando comando — é idêntica.)
- **Flag:** `FLAG{command_injection_no_ping}` (conteúdo de `storage/flag_cmd.txt`).
- **Impacto:** execução de comandos no servidor.
- **CWE:** 78, 77.
- **Correção:** validar o host por allowlist (`^[A-Za-z0-9.\-]+$`) e **não** montar
  linha de shell com a entrada (usar APIs com argumentos separados / `escapeshellarg`).

### 6) XXE na importação de notas — 150 pts
- **Onde:** `importar.php` (cola de XML).
- **Explorar:**
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///CAMINHO/aula02/storage/flag_xxe.txt">]>
  <notas><aluno>&xxe;</aluno></notas>
  ```
  (a própria página mostra o caminho absoluto do arquivo-alvo). A entidade externa
  é expandida e o conteúdo do arquivo aparece na tela.
- **Flag:** `FLAG{xxe_leu_arquivo_do_servidor}`.
- **Impacto:** leitura de arquivos do servidor (e SSRF via `http://`).
- **CWE:** 611, 827, 776.
- **Correção:** desabilitar DTD/entidades externas (`libxml_set_external_entity_loader(fn()=>null)`,
  `LIBXML_NONET`) e recusar `<!DOCTYPE>`/`<!ENTITY>`.

---

## A02 — Security Misconfiguration

### 7) Credencial de fábrica no console legado — 120 pts
- **Onde:** `admin-legado/` (Console de Administração v1.2).
- **Explorar:** entre com `admin` / `admin123` — padrão de fábrica que ninguém
  trocou (a dica está até no comentário do HTML).
- **Flag:** `FLAG{credencial_de_fabrica_no_console}`.
- **Impacto:** acesso administrativo imediato por credencial conhecida.
- **CWE:** 798, 1392, 1188.
- **Correção:** bloquear a credencial de fábrica e exigir troca no 1º acesso.

### 8) Erro verboso (stack trace / SQL na tela) — 110 pts
- **Onde:** `exportar.php`
- **Explorar:** `?col=xyz` (coluna inexistente) provoca erro de SQL. Em modo
  vulnerável o app despeja a exceção, a query, o caminho do arquivo e um
  "contexto de depuração" com `APP_SECRET` e a flag.
- **Flag:** `FLAG{stack_trace_vazou_segredo}`.
- **Impacto:** vazamento de detalhes internos que facilitam outros ataques.
- **CWE:** 209, 497, 756.
- **Correção:** mensagem genérica ao usuário; detalhes só no log do servidor
  (`error_log`), com `display_errors=Off` em produção.

### 9) Modo debug exposto — 100 pts
- **Onde:** `status.php`
- **Explorar:** `?debug=1` liga um painel de depuração que imprime config, credenciais
  do banco, `APP_SECRET` e a flag.
- **Flag:** `FLAG{modo_debug_exposto}`.
- **Impacto:** exposição de configuração e segredos.
- **CWE:** 489, 16, 215.
- **Correção:** remover código de debug de produção; em MODO SEGURO o `?debug`
  é ignorado.

### 10) CORS mal configurado — 120 pts
- **Onde:** `api/relatorio.php`
- **Explorar:** a API reflete qualquer `Origin` e envia
  `Access-Control-Allow-Credentials: true` — um site malicioso aberto pela vítima
  consegue ler a resposta autenticada. Teste:
  `curl -H "Origin: http://evil.test" .../api/relatorio.php -i`.
- **Flag:** `FLAG{cors_liberou_geral}` (no corpo JSON).
- **Impacto:** vazamento de dados cross-origin com as credenciais da vítima.
- **CWE:** 942, 346.
- **Correção:** allowlist de origens; nunca combinar `*`/reflexo de origem com
  credenciais.

### 11) Cabeçalhos de segurança ausentes (clickjacking) — 90 pts
- **Onde:** `headers.php` + isca `clickjack_poc.html`.
- **Explorar:** sem `X-Frame-Options`/CSP `frame-ancestors`, o portal pode ser
  embutido num `<iframe>` de outro site. Abra `clickjack_poc.html`: ele enquadra
  o portal com sucesso. A página `headers.php` revela a flag em modo vulnerável.
- **Flag:** `FLAG{sem_x_frame_options_clickjacking}`.
- **Impacto:** clickjacking (UI redressing); ausência de defesas no navegador.
- **CWE:** 1021, 693, 16.
- **Correção:** enviar `X-Frame-Options: DENY`, CSP com `frame-ancestors 'none'`,
  `X-Content-Type-Options: nosniff` etc. (feito em `lib/render.php` no MODO SEGURO).

---

## Encerramento sugerido
1. Ligue o MODO SEGURO e repasse 2–3 missões mostrando o ataque falhar.
2. Reforce o princípio por categoria: **Injection** = nunca misture dados com
   código/comando (parametrize, escape, valide); **Misconfiguration** = endureça
   padrões, remova o que é de desenvolvimento, controle cabeçalhos e segredos.
3. Limpeza: veja `LEIA-ME.md` (derrubar o site e apagar o banco).
