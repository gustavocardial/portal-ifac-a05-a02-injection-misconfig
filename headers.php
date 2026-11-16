<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';
$b = base_url();

/**
 * MISSÃO HEADERS — Cabeçalhos de segurança ausentes (A02 / CWE-1021, CWE-693).
 * Sem X-Frame-Options / CSP frame-ancestors, a página pode ser embutida em um
 * <iframe> de outro site e usada para clickjacking. Os cabeçalhos só são
 * enviados em MODO SEGURO (ver lib/render.php:enviar_headers_seguranca).
 */
$esperados = ['X-Frame-Options', 'Content-Security-Policy',
              'X-Content-Type-Options', 'Referrer-Policy'];
// Em modo vulnerável nenhum é enviado; em modo seguro, todos.
$presentes = SECURE ? $esperados : [];

page_header('Cabeçalhos de segurança');
?>
<div class="card">
  <h2>Cabeçalhos de segurança da resposta</h2>
  <table>
    <tr><th>Cabeçalho</th><th>Presente?</th></tr>
    <?php foreach ($esperados as $h): $ok = in_array($h, $presentes, true); ?>
      <tr><td class="mono"><?= e($h) ?></td>
          <td style="color:<?= $ok ? 'var(--secure)' : 'var(--vuln)' ?>">
            <?= $ok ? '✔ enviado' : '✗ ausente' ?></td></tr>
    <?php endforeach; ?>
  </table>
</div>

<?php if (!SECURE): ?>
<div class="card" style="border-color:var(--vuln)">
  <h3>🏴 Sem proteção contra enquadramento</h3>
  <p class="muted">Sem <code>X-Frame-Options</code> nem <code>frame-ancestors</code>,
     esta página pode ser carregada dentro de um <code>&lt;iframe&gt;</code> de
     outro site — base para <strong>clickjacking</strong>. Abra a isca
     <a href="<?= e($b) ?>/clickjack_poc.html" target="_blank">clickjack_poc.html</a>:
     ela consegue embutir o portal. Em modo seguro, o mesmo teste falha.</p>
  <p>Flag: <span class="flag"><?= e(flags_catalogo()['HEADERS']['flag']) ?></span></p>
</div>
<?php else: ?>
<div class="card"><div class="alert ok">
  Cabeçalhos de proteção presentes — enquadramento por terceiros é bloqueado. ✔
</div></div>
<?php endif; ?>
<?php page_footer();
