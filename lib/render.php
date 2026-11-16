<?php
/**
 * Layout compartilhado (cabeçalho, rodapé, helpers de HTML).
 * CSS inline para funcionar OFFLINE na rede local do laboratório.
 */
require_once __DIR__ . '/auth.php';

function e(?string $s): string {
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

/**
 * Cabeçalhos de segurança (missão HEADERS — A02 / CWE-1021, CWE-693, CWE-16).
 * Vulnerável: nenhum cabeçalho de proteção -> a página pode ser embutida em
 *   um <iframe> de outro site (clickjacking) e o navegador não tem CSP.
 * Corrigido: enviamos X-Frame-Options, CSP, X-Content-Type-Options, etc.
 */
function enviar_headers_seguranca(): void {
    if (headers_sent()) {
        return;
    }
    if (SECURE) {
        header('X-Frame-Options: DENY');
        header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; "
             . "script-src 'self'; style-src 'self' 'unsafe-inline'");
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: same-origin');
        header_remove('X-Powered-By');
    }
    // Modo vulnerável: de propósito, não enviamos nada disso.
}

function page_header(string $titulo): void {
    enviar_headers_seguranca();
    $u = current_user();
    $b = base_url();
    $modo = SECURE
        ? '<span class="pill pill-secure">MODO SEGURO</span>'
        : '<span class="pill pill-vuln">MODO VULNERÁVEL</span>';
    $toggleTo  = SECURE ? 'off' : 'on';
    $toggleTxt = SECURE ? 'Desligar correções' : 'Ligar correções';
    echo <<<HTML
<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{$titulo} — Portal Acadêmico IFAC (Aula 2)</title>
<style>
  :root{--bg:#0f1420;--card:#1a2233;--ink:#e8edf6;--mut:#9fb0c9;--line:#2b3850;
        --accent:#4f8cff;--vuln:#ff5c7a;--secure:#2ecc71;}
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.5 system-ui,Segoe UI,Roboto,Arial,sans-serif;
       background:var(--bg);color:var(--ink)}
  a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
  header.top{display:flex;align-items:center;gap:14px;flex-wrap:wrap;
       padding:12px 20px;background:#0b1220;border-bottom:1px solid var(--line)}
  header.top .brand{font-weight:700;letter-spacing:.3px}
  header.top nav{display:flex;gap:14px;flex-wrap:wrap}
  header.top .spacer{flex:1}
  .wrap{max-width:960px;margin:24px auto;padding:0 16px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;
        padding:18px 20px;margin:14px 0}
  .pill{font-size:12px;font-weight:700;padding:3px 10px;border-radius:999px}
  .pill-vuln{background:rgba(255,92,122,.15);color:var(--vuln);border:1px solid var(--vuln)}
  .pill-secure{background:rgba(46,204,113,.15);color:var(--secure);border:1px solid var(--secure)}
  .btn{display:inline-block;background:var(--accent);color:#fff;padding:8px 14px;
       border-radius:8px;border:0;cursor:pointer;font:inherit}
  .btn.ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}
  input,select,textarea{background:#0b1220;border:1px solid var(--line);color:var(--ink);
       padding:8px 10px;border-radius:8px;font:inherit;width:100%}
  label{display:block;margin:10px 0 4px;color:var(--mut);font-size:13px}
  table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid var(--line);text-align:left}
  .muted{color:var(--mut)} .mono{font-family:ui-monospace,Consolas,monospace}
  .flag{display:inline-block;background:#05281a;border:1px dashed var(--secure);
        color:#7bffb0;padding:6px 10px;border-radius:8px;font-family:ui-monospace,monospace}
  .cwe{font-size:12px;color:var(--mut)}
  .alert{padding:10px 12px;border-radius:8px;margin:10px 0}
  .alert.ok{background:rgba(46,204,113,.12);border:1px solid var(--secure)}
  .alert.err{background:rgba(255,92,122,.12);border:1px solid var(--vuln)}
  pre.dump{background:#0b1220;border:1px solid var(--line);border-radius:8px;
        padding:12px;overflow:auto;font-size:12px;color:#ffb0c0}
</style>
</head>
<body>
<header class="top">
  <span class="brand">🎓 Portal Acadêmico IFAC · Aula 2</span>
  <nav>
    <a href="{$b}/index.php">Início</a>
    <a href="{$b}/dashboard.php">Painel</a>
    <a href="{$b}/placar.php">Placar</a>
HTML;
    if ($u) {
        echo '<a href="' . e($b) . '/perfil.php">Meu perfil</a>';
        echo '<a href="' . e($b) . '/logout.php">Sair (' . e($u['nome']) . ')</a>';
    } else {
        echo '<a href="' . e($b) . '/login.php">Entrar</a>';
    }
    echo <<<HTML
  </nav>
  <span class="spacer"></span>
  {$modo}
  <a class="btn ghost" href="?toggle_secure={$toggleTo}">{$toggleTxt}</a>
</header>
<div class="wrap">
HTML;
}

function page_footer(): void {
    $b = base_url();
    echo <<<HTML
</div>
<footer class="wrap muted" style="margin-top:30px;font-size:13px">
  <hr style="border-color:var(--line)">
  Aplicação <strong>deliberadamente vulnerável</strong> — material didático
  (OWASP Top 10 2025 · A05 Injection + A02 Security Misconfiguration).
  Uso restrito a laboratório.
</footer>
<script src="{$b}/assets/js/app.js"></script>
</body>
</html>
HTML;
}
