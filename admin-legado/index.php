<?php
require_once __DIR__ . '/../lib/render.php';
require_once __DIR__ . '/../lib/flags.php';
$b = base_url();

/**
 * MISSÃO DEFAULTCRED — Credencial de fábrica (A02 / CWE-798, CWE-1392, CWE-1188).
 * "Console de Administração Legado" instalado com usuário/senha padrão de fábrica
 * que ninguém trocou. Em modo seguro, a conta de fábrica é bloqueada.
 */
const CONSOLE_USER = 'admin';
const CONSOLE_PASS = 'admin123';   // padrão de fábrica — NUNCA alterado

$erro = null; $entrou = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $us = (string) ($_POST['u'] ?? '');
    $pw = (string) ($_POST['p'] ?? '');
    $credencialDeFabrica = hash_equals(CONSOLE_USER, $us) && hash_equals(CONSOLE_PASS, $pw);
    if (SECURE) {
        // Corrigido: a credencial de fábrica é recusada (troca obrigatória).
        $erro = $credencialDeFabrica
            ? 'Credencial de fábrica desativada. Defina uma senha no primeiro acesso.'
            : 'Acesso negado.';
    } elseif ($credencialDeFabrica) {
        $entrou = true;
    } else {
        $erro = 'Acesso negado.';
    }
}

page_header('Console Legado');
?>
<div class="card">
  <h2>🗄️ Console de Administração Legado <span class="muted">v1.2</span></h2>
  <?php if ($entrou): ?>
    <div class="alert ok">Autenticado no console com a credencial de fábrica.</div>
    <h3>🏴 Credencial de fábrica!</h3>
    <p class="muted">O console foi instalado com <code>admin / admin123</code> e
       ninguém trocou. Flag:</p>
    <p><span class="flag"><?= e(flags_catalogo()['DEFAULTCRED']['flag']) ?></span></p>
  <?php else: ?>
    <?php if ($erro): ?><div class="alert err"><?= e($erro) ?></div><?php endif; ?>
    <form method="post">
      <label>Usuário</label><input name="u" autocomplete="off">
      <label>Senha</label><input type="password" name="p" autocomplete="off">
      <div style="margin-top:12px"><button class="btn">Acessar console</button></div>
    </form>
    <!-- NOTA DE INSTALAÇÃO (deixada no HTML por engano):
         credenciais de fábrica = admin / admin123 — trocar no 1º acesso. -->
    <p class="muted" style="font-size:12px;margin-top:10px">
      Console de fábrica. Consulte o manual do fornecedor para as credenciais
      iniciais (dica A02: às vezes elas vêm no próprio código-fonte da página…).</p>
  <?php endif; ?>
</div>
<?php page_footer();
