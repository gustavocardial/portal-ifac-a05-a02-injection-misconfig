<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';
$b = base_url();

/**
 * MISSÃO VERBOSE — Erro verboso (A02 / CWE-209, CWE-497, CWE-756).
 * Exporta boletins ordenados por uma coluna escolhida. Se a coluna for inválida,
 * o banco lança erro. Em modo vulnerável (DEBUG), o app despeja a mensagem do
 * SGBD, a query e um "contexto de depuração" com segredos na tela.
 */
$col = (string) ($_GET['col'] ?? 'nota');
$linhas = [];
$falhou = false;

try {
    // A coluna entra direta no ORDER BY (não deveria!). Coluna inexistente -> erro.
    $sql = "SELECT disciplina, nota, situacao FROM boletins ORDER BY $col DESC LIMIT 20";
    $linhas = db()->query($sql)->fetchAll();
} catch (Throwable $ex) {
    $falhou = true;
    if (SECURE || !DEBUG) {
        // ---- Corrigido: mensagem genérica, detalhes só no log do servidor.
        error_log('[exportar] ' . $ex->getMessage());
        $saidaErro = 'Não foi possível gerar o relatório. Tente novamente mais tarde.';
    } else {
        // ---- VULNERÁVEL: detalhes internos despejados na resposta.
        $saidaErro = "EXCEÇÃO: " . $ex->getMessage() . "\n\n"
            . "QUERY: $sql\n\n"
            . "ARQUIVO: " . $ex->getFile() . ':' . $ex->getLine() . "\n\n"
            . "STACK TRACE:\n" . $ex->getTraceAsString() . "\n\n"
            . "-- contexto de depuração --\n"
            . "APP_SECRET = " . APP_SECRET . "\n"
            . "DB = " . DB_USER . '@' . DB_HOST . '/' . DB_NAME . "\n"
            . "FLAG = " . flags_catalogo()['VERBOSE']['flag'] . "\n";
    }
}

page_header('Exportar relatório');
?>
<div class="card">
  <h2>Exportar relatório de boletins</h2>
  <form method="get">
    <label>Ordenar por coluna</label>
    <input name="col" value="<?= e($col) ?>" class="mono">
    <div style="margin-top:12px"><button class="btn">Gerar</button></div>
  </form>
  <?php if (!SECURE): ?>
  <p class="muted" style="font-size:12px;margin-top:10px">
    Dica A02: e se a coluna não existir? Ex.: <code class="mono">?col=xyz</code> —
    veja o que o sistema conta sobre si mesmo quando dá erro.</p>
  <?php endif; ?>
</div>

<?php if ($falhou): ?>
<div class="card" style="border-color:var(--vuln)">
  <h3>Erro ao gerar relatório</h3>
  <pre class="dump"><?= e($saidaErro) ?></pre>
  <?php if (!SECURE && DEBUG): ?>
    <p>Flag: <span class="flag"><?= e(flags_catalogo()['VERBOSE']['flag']) ?></span></p>
  <?php endif; ?>
</div>
<?php elseif ($linhas): ?>
<div class="card">
  <h3>Relatório</h3>
  <table>
    <tr><th>Disciplina</th><th>Nota</th><th>Situação</th></tr>
    <?php foreach ($linhas as $l): ?>
      <tr><td><?= e($l['disciplina']) ?></td><td><?= e($l['nota']) ?></td><td><?= e($l['situacao']) ?></td></tr>
    <?php endforeach; ?>
  </table>
</div>
<?php endif; ?>
<?php page_footer();
