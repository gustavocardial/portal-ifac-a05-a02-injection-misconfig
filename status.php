<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';
$b = base_url();

/**
 * MISSÃO DEBUGPARAM — Modo debug exposto (A02 / CWE-489, CWE-16, CWE-215).
 * Página de status "de saúde" do sistema. Um resquício de desenvolvimento deixou
 * um parâmetro ?debug=1 que, em produção, despeja configuração e segredos.
 */
$debug = isset($_GET['debug']) && $_GET['debug'] === '1';

page_header('Status do sistema');
?>
<div class="card">
  <h2>Status do sistema</h2>
  <table>
    <tr><td>Aplicação</td><td>Portal Acadêmico IFAC — Aula 2</td></tr>
    <tr><td>Estado</td><td style="color:var(--secure)">● no ar</td></tr>
    <tr><td>Hora do servidor</td><td class="mono"><?= e(date('c')) ?></td></tr>
    <tr><td>PHP</td><td class="mono"><?= e(PHP_VERSION) ?></td></tr>
  </table>
</div>

<?php if ($debug && !SECURE && DEBUG): ?>
<div class="card" style="border-color:var(--vuln)">
  <h3>🔧 DEBUG — contexto de execução</h3>
  <p class="muted">Painel de depuração (jamais deveria responder em produção).</p>
  <pre class="dump"><?php
    $ctx = [
      'SECURE'      => SECURE ? 'true' : 'false',
      'DEBUG'       => DEBUG ? 'true' : 'false',
      'DB_HOST'     => DB_HOST,
      'DB_USER'     => DB_USER,
      'DB_PASS'     => DB_PASS === '' ? '(vazia)' : DB_PASS,
      'DB_NAME'     => DB_NAME,
      'APP_SECRET'  => APP_SECRET,
      'session_id'  => session_id(),
      'DEBUG_FLAG'  => flags_catalogo()['DEBUGPARAM']['flag'],
    ];
    foreach ($ctx as $k => $v) {
        echo e(str_pad($k, 12)) . ' = ' . e((string) $v) . "\n";
    }
  ?></pre>
  <p>Flag: <span class="flag"><?= e(flags_catalogo()['DEBUGPARAM']['flag']) ?></span></p>
</div>
<?php elseif ($debug && SECURE): ?>
<div class="card"><div class="alert ok">Modo debug desativado em produção. ✔</div></div>
<?php else: ?>
<p class="muted">Tudo certo por aqui. <span style="opacity:.5">(dica A02: será que
  esta página aceita algum parâmetro de depuração?)</span></p>
<?php endif; ?>
<?php page_footer();
